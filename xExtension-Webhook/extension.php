<?php

declare(strict_types=1);

include __DIR__ . '/request.php';

/**
 * Enumeration for HTTP request body types.
 */
enum BODY_TYPE: string {
	case JSON = 'json';
	case FORM = 'form';
}

/**
 * Enumeration for HTTP methods.
 */
enum HTTP_METHOD: string {
	case GET = 'GET';
	case POST = 'POST';
	case PUT = 'PUT';
	case DELETE = 'DELETE';
	case PATCH = 'PATCH';
	case OPTIONS = 'OPTIONS';
	case HEAD = 'HEAD';
}

/**
 * FreshRSS Webhook Extension
 *
 * Sends configurable webhook requests whenever new entries match the
 * configured keyword filters.
 *
 * @author Lukas Melega, Ryahn, onlymykazari
 * @version 0.3.0
 * @since FreshRSS 1.20.0
 */
	final class WebhookExtension extends Minz_Extension {
		private const DEFAULT_URL = 'http://<WRITE YOUR URL HERE>';
		/** @var list<string> */
		private const DEFAULT_HEADERS = [
		'User-Agent: FreshRSS',
		'Content-Type: application/json',
	];
	private const DEFAULT_BODY_TEMPLATE = '{
	"title": "__TITLE__",
	"feed": "__FEED__",
	"url": "__URL__",
	"created": "__DATE_TIMESTAMP__"
}';
	private const DEFAULT_METHOD = HTTP_METHOD::POST;
	private const DEFAULT_BODY_TYPE = BODY_TYPE::JSON;
	private const MATCH_MODE_BASIC = 'basic';
	private const MATCH_MODE_ADVANCED = 'advanced';
	private const JSON_LOG_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
	private const PLAINTEXT_MAX_LENGTH = 360;

	private bool $logsEnabled = false;

	#[\Override]
	public function init(): void {
		$this->registerTranslates();
		$this->ensureConfigurationDefaults();
		$this->registerHook('entry_before_insert', [$this, 'processArticle']);
	}

	/**
	 * @throws Minz_PermissionDeniedException
	 */
	#[\Override]
	public function handleConfigureAction(): void {
		$this->registerTranslates();

		if (!Minz_Request::isPost()) {
			return;
		}

		$userConf = $this->getUserConf();
		if ($userConf === null) {
			throw new Minz_PermissionDeniedException('Webhook configuration requires an authenticated user.');
		}

		$config = $this->collectConfigurationFromRequest();

		foreach ($config as $key => $value) {
			$userConf->_attribute($key, $value);
		}

		$userConf->save();

		$this->logsEnabled = $config['enable_logging'];

		$loggable = $config;
		$loggable['webhook_body'] = '[redacted]';
		logWarning(
			$this->logsEnabled,
			'Webhook configuration saved: ' . json_encode($loggable, self::JSON_LOG_FLAGS)
		);

		if ($this->shouldSendTestRequest()) {
			$this->sendTestRequestSafely($config);
		}
	}

	/**
	 * Process article and send webhook if patterns match.
	 */
	public function processArticle(FreshRSS_Entry $entry): FreshRSS_Entry {
		$config = $this->getSnapshot();
		if ($config === null) {
			return $entry;
		}

		$this->logsEnabled = $config['enable_logging'];

		if ($config['ignore_updated'] && $entry->isUpdated()) {
			logWarning(
				$this->logsEnabled,
				'Ignoring updated entry: ' . $entry->link() . ' ♦ ' . $entry->title()
			);
			return $entry;
		}

		if (!$this->hasConfiguredKeywords($config)) {
			logWarning($this->logsEnabled, 'No keywords defined in Webhook extension settings.');
			return $entry;
		}

		$matchLog = $config['match_mode'] === self::MATCH_MODE_ADVANCED
			? $this->findMatchLogAdvanced($entry, $config)
			: $this->findMatchLogBasic($entry, $config);

		if ($matchLog === null) {
			return $entry;
		}

		if ($config['mark_as_read']) {
			$entry->_isRead(true);
		}

		$this->sendArticle($entry, $matchLog, $config);

		return $entry;
	}

	/**
	 * Try to find a pattern that matches this entry in basic mode.
	 *
	 * @param array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * } $config
	 */
	private function findMatchLogBasic(FreshRSS_Entry $entry, array $config): ?string {
		$patterns = $config['keywords'];
		if ($patterns === []) {
			return null;
		}

		$title = $entry->title();
		$link = $entry->link();
		$feed = $entry->feed();
		$feedName = $feed instanceof FreshRSS_Feed ? $feed->name() : '';
		$authors = trim($entry->authors(true));
		$content = $entry->content();

		foreach ($patterns as $pattern) {
			$normalizedPattern = $this->normalizePattern($pattern);
			if ($normalizedPattern === null) {
				continue;
			}

			if ($config['search_in_title'] && $this->isPatternFound($normalizedPattern, $title, $pattern)) {
				return "Matched by title ⮕ pattern: {$pattern} ♦ title: {$title} ♦ link: {$link}";
			}

			if (
				$config['search_in_feed']
				&& $feedName !== ''
				&& $this->isPatternFound($normalizedPattern, $feedName, $pattern)
			) {
				return "Matched by feed ⮕ pattern: {$pattern} ♦ feed: {$feedName} ♦ link: {$link}";
			}

			if (
				$config['search_in_authors']
				&& $authors !== ''
				&& $this->isPatternFound($normalizedPattern, $authors, $pattern)
			) {
				return "Matched by authors ⮕ pattern: {$pattern} ♦ authors: {$authors} ♦ link: {$link}";
			}

			if (
				$config['search_in_content']
				&& $content !== ''
				&& $this->isPatternFound($normalizedPattern, $content, $pattern)
			) {
				return "Matched by content ⮕ pattern: {$pattern} ♦ title: {$title} ♦ link: {$link}";
			}
		}

		return null;
	}

	/**
	 * Try to find a pattern that matches this entry in advanced mode.
	 *
	 * @param array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * } $config
	 */
	private function findMatchLogAdvanced(FreshRSS_Entry $entry, array $config): ?string {
		$title = $entry->title();
		$link = $entry->link();
		$feed = $entry->feed();
		$feedName = $feed instanceof FreshRSS_Feed ? $feed->name() : '';
		$authors = trim($entry->authors(true));
		$content = $entry->content();

		foreach ($config['keywords_title'] as $pattern) {
			$normalizedPattern = $this->normalizePattern($pattern);
			if ($normalizedPattern !== null && $this->isPatternFound($normalizedPattern, $title, $pattern)) {
				return "Matched by title ⮕ pattern: {$pattern} ♦ title: {$title} ♦ link: {$link}";
			}
		}

		foreach ($config['keywords_feed'] as $pattern) {
			$normalizedPattern = $this->normalizePattern($pattern);
			if (
				$normalizedPattern !== null
				&& $feedName !== ''
				&& $this->isPatternFound($normalizedPattern, $feedName, $pattern)
			) {
				return "Matched by feed ⮕ pattern: {$pattern} ♦ feed: {$feedName} ♦ link: {$link}";
			}
		}

		foreach ($config['keywords_authors'] as $pattern) {
			$normalizedPattern = $this->normalizePattern($pattern);
			if (
				$normalizedPattern !== null
				&& $authors !== ''
				&& $this->isPatternFound($normalizedPattern, $authors, $pattern)
			) {
				return "Matched by authors ⮕ pattern: {$pattern} ♦ authors: {$authors} ♦ link: {$link}";
			}
		}

		foreach ($config['keywords_content'] as $pattern) {
			$normalizedPattern = $this->normalizePattern($pattern);
			if (
				$normalizedPattern !== null
				&& $content !== ''
				&& $this->isPatternFound($normalizedPattern, $content, $pattern)
			) {
				return "Matched by content ⮕ pattern: {$pattern} ♦ title: {$title} ♦ link: {$link}";
			}
		}

		return null;
	}

	/**
	 * @param array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * } $config
	 */
	private function hasConfiguredKeywords(array $config): bool {
		if ($config['match_mode'] === self::MATCH_MODE_ADVANCED) {
			return $config['keywords_title'] !== []
				|| $config['keywords_feed'] !== []
				|| $config['keywords_authors'] !== []
				|| $config['keywords_content'] !== [];
		}

		return $config['keywords'] !== [];
	}

	/**
	 * Send article data via webhook.
	 *
	 * @param array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * } $config
	 */
	private function sendArticle(FreshRSS_Entry $entry, string $additionalLog, array $config): void {
		try {
			$bodyTemplate = $config['webhook_body'];
			$replacements = $this->buildReplacements($entry);
			$body = str_replace(array_keys($replacements), array_values($replacements), $bodyTemplate);

			sendReq(
				$config['webhook_url'],
				$config['webhook_method'],
				$config['webhook_body_type'],
				$body,
				$config['webhook_headers'],
				$config['enable_logging'],
				$additionalLog,
			);
		} catch (RuntimeException|InvalidArgumentException|JsonException $err) {
			logError($this->logsEnabled, 'sendArticle error: ' . $err->getMessage());
		}
	}

	/**
	 * Send a manual test request using configuration data.
	 *
	 * @throws InvalidArgumentException
	 * @throws JsonException
	 * @throws RuntimeException
	 *
	 * @param array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * } $config
	 */
	private function sendTestRequest(array $config): void {
		sendReq(
			$config['webhook_url'],
			$config['webhook_method'],
			$config['webhook_body_type'],
			$config['webhook_body'],
			$config['webhook_headers'],
			$config['enable_logging'],
			'Test request from configuration',
		);
	}

	/**
	 * Keep configuration save path resilient even when test webhook fails.
	 *
	 * @param array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * } $config
	 */
	private function sendTestRequestSafely(array $config): void {
		try {
			$this->sendTestRequest($config);
		} catch (RuntimeException|InvalidArgumentException|JsonException $err) {
			logError($this->logsEnabled, 'Test webhook request failed: ' . $err->getMessage());
		}
	}

	/**
	 * Build placeholder replacements for the configured template.
	 *
	 * @return array<string, string>
	 */
	private function buildReplacements(FreshRSS_Entry $entry): array {
		$feed = $entry->feed();
		$feedName = $feed instanceof FreshRSS_Feed ? $feed->name() : '';

		return [
			'__TITLE__' => $this->toSafeJsonStr($entry->title()),
			'__FEED__' => $this->toSafeJsonStr($feedName),
			'__URL__' => $this->toSafeJsonStr($entry->link()),
			'__CONTENT__' => $this->toSafeJsonStr($entry->content()),
			'__DATE__' => $this->toSafeJsonStr($entry->date()),
			'__DATE_TIMESTAMP__' => $this->toSafeJsonStr($entry->date(true)),
			'__AUTHORS__' => $this->toSafeJsonStr($entry->authors(true)),
			'__TAGS__' => $this->toSafeJsonStr($entry->tags(true)),
			'__THUMBNAIL_URL__' => $this->toSafeJsonStr($this->getEntryThumbnail($entry)),
			'__CONTENT_PLAINTEXT__' => $this->toSafeJsonStr($this->getPlainTextContent($entry)),
		];
	}

	/**
	 * Convert a mixed value to a JSON-safe string.
	 */
	private function toSafeJsonStr(mixed $value): string {
		if ($value === null) {
			return '';
		}

		if ($value instanceof DateTimeInterface) {
			return $value->format(DateTimeInterface::ATOM);
		}

		if (is_array($value)) {
			$items = [];
			foreach ($value as $item) {
				$items[] = $this->normalizeScalarToString($item);
			}
			$value = implode(', ', $items);
		} elseif (is_object($value)) {
			if (method_exists($value, '__toString')) {
				$value = (string) $value;
			} else {
				return '';
			}
		}

			$string = html_entity_decode($this->normalizeScalarToString($value), ENT_QUOTES | ENT_HTML5, 'UTF-8');
			$string = preg_replace('/\s+/u', ' ', $string) ?? '';

		return addcslashes(trim($string), "\"\\");
	}

	private function normalizeScalarToString(mixed $value): string {
		if ($value === null) {
			return '';
		}
		if (is_scalar($value)) {
			return (string) $value;
		}
		if ($value instanceof DateTimeInterface) {
			return $value->format(DateTimeInterface::ATOM);
		}
		if (is_object($value) && method_exists($value, '__toString')) {
			return (string) $value;
		}

		return '';
	}

	/**
	 * Ensure configuration defaults exist for the current user.
	 */
	private function ensureConfigurationDefaults(): void {
		$userConf = $this->getUserConf();
		if ($userConf === null) {
			return;
		}

		$needsSave = $this->migrateLegacyConfiguration($userConf);

		if ($userConf->attributeArray('keywords') === null) {
			$userConf->_attribute('keywords', []);
			$needsSave = true;
		}
		if ($userConf->attributeString('match_mode') === null) {
			$userConf->_attribute('match_mode', self::MATCH_MODE_BASIC);
			$needsSave = true;
		}
		if ($userConf->attributeArray('keywords_title') === null) {
			$userConf->_attribute('keywords_title', []);
			$needsSave = true;
		}
		if ($userConf->attributeArray('keywords_feed') === null) {
			$userConf->_attribute('keywords_feed', []);
			$needsSave = true;
		}
		if ($userConf->attributeArray('keywords_authors') === null) {
			$userConf->_attribute('keywords_authors', []);
			$needsSave = true;
		}
		if ($userConf->attributeArray('keywords_content') === null) {
			$userConf->_attribute('keywords_content', []);
			$needsSave = true;
		}

		$needsSave = $this->ensureBoolDefault($userConf, 'search_in_title', true) || $needsSave;
		$needsSave = $this->ensureBoolDefault($userConf, 'search_in_feed', false) || $needsSave;
		$needsSave = $this->ensureBoolDefault($userConf, 'search_in_authors', false) || $needsSave;
		$needsSave = $this->ensureBoolDefault($userConf, 'search_in_content', false) || $needsSave;
		$needsSave = $this->ensureBoolDefault($userConf, 'mark_as_read', false) || $needsSave;
		$needsSave = $this->ensureBoolDefault($userConf, 'ignore_updated', false) || $needsSave;
		$needsSave = $this->ensureBoolDefault($userConf, 'enable_logging', false) || $needsSave;

		if ($userConf->attributeString('webhook_url') === null) {
			$userConf->_attribute('webhook_url', self::DEFAULT_URL);
			$needsSave = true;
		}

		if ($userConf->attributeString('webhook_method') === null) {
			$userConf->_attribute('webhook_method', self::DEFAULT_METHOD->value);
			$needsSave = true;
		}

		if ($userConf->attributeArray('webhook_headers') === null) {
			$userConf->_attribute('webhook_headers', self::DEFAULT_HEADERS);
			$needsSave = true;
		}

		if ($userConf->attributeString('webhook_body') === null) {
			$userConf->_attribute('webhook_body', self::DEFAULT_BODY_TEMPLATE);
			$needsSave = true;
		}

		if ($userConf->attributeString('webhook_body_type') === null) {
			$userConf->_attribute('webhook_body_type', self::DEFAULT_BODY_TYPE->value);
			$needsSave = true;
		}

		if ($needsSave) {
			$userConf->save();
		}
	}

	/**
	 * Attempt to migrate settings stored via the legacy system configuration.
	 */
	private function migrateLegacyConfiguration(FreshRSS_UserConfiguration $userConf): bool {
		$legacy = $this->getSystemConfiguration();
		if ($legacy === []) {
			return false;
		}

		$needsSave = false;
		$map = [
			'keywords' => ['type' => 'array'],
			'match_mode' => ['type' => 'string'],
			'keywords_title' => ['type' => 'array'],
			'keywords_feed' => ['type' => 'array'],
			'keywords_authors' => ['type' => 'array'],
			'keywords_content' => ['type' => 'array'],
			'search_in_title' => ['type' => 'bool'],
			'search_in_feed' => ['type' => 'bool'],
			'search_in_authors' => ['type' => 'bool'],
			'search_in_content' => ['type' => 'bool'],
			'mark_as_read' => ['type' => 'bool'],
			'ignore_updated' => ['type' => 'bool'],
			'webhook_url' => ['type' => 'string'],
			'webhook_method' => ['type' => 'string'],
			'webhook_headers' => ['type' => 'array'],
			'webhook_body' => ['type' => 'string'],
			'webhook_body_type' => ['type' => 'string'],
			'enable_logging' => ['type' => 'bool'],
		];

		foreach ($map as $key => $meta) {
			if (!array_key_exists($key, $legacy)) {
				continue;
			}

			if ($this->hasAttributeValue($userConf, $key, $meta['type'])) {
				continue;
			}

			$userConf->_attribute($key, $legacy[$key]);
			$needsSave = true;
		}

		if ($needsSave) {
			logWarning(true, 'Webhook settings migrated from system scope to per-user scope.');
		}

		return $needsSave;
	}

	private function hasAttributeValue(FreshRSS_UserConfiguration $userConf, string $key, string $type): bool {
		/** @var non-empty-string $key */
		return match ($type) {
			'array' => $userConf->attributeArray($key) !== null,
			'bool' => $userConf->attributeBool($key) !== null,
			default => $userConf->attributeString($key) !== null,
		};
	}

	private function ensureBoolDefault(FreshRSS_UserConfiguration $userConf, string $key, bool $default): bool {
		/** @var non-empty-string $key */
		if ($userConf->attributeBool($key) === null) {
			$userConf->_attribute($key, $default);
			return true;
		}

		return false;
	}

	private function getUserConf(): ?FreshRSS_UserConfiguration {
		try {
			if (!FreshRSS_Context::hasUserConf()) {
				return null;
			}

			return FreshRSS_Context::userConf();
		} catch (FreshRSS_Context_Exception $exception) {
			return null;
		}
	}

	/**
	 * Collect configuration values from the current request payload.
	 *
	 * @return array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * }
	 */
	private function collectConfigurationFromRequest(): array {
		$keywords = $this->normalizeListInput(Minz_Request::paramTextToArray('keywords'));
		$keywordsTitle = $this->normalizeListInput(Minz_Request::paramTextToArray('keywords_title'));
		$keywordsFeed = $this->normalizeListInput(Minz_Request::paramTextToArray('keywords_feed'));
		$keywordsAuthors = $this->normalizeListInput(Minz_Request::paramTextToArray('keywords_authors'));
		$keywordsContent = $this->normalizeListInput(Minz_Request::paramTextToArray('keywords_content'));
		$headers = $this->normalizeListInput(Minz_Request::paramTextToArray('webhook_headers'));
		$headers = $headers === [] ? self::DEFAULT_HEADERS : $headers;

		$methodValue = HTTP_METHOD::tryFrom(strtoupper(Minz_Request::paramString('webhook_method')));
		$bodyTypeValue = BODY_TYPE::tryFrom(strtolower(Minz_Request::paramString('webhook_body_type')));
		$matchMode = Minz_Request::paramString('match_mode');
		if (!in_array($matchMode, [self::MATCH_MODE_BASIC, self::MATCH_MODE_ADVANCED], true)) {
			$matchMode = self::MATCH_MODE_BASIC;
		}

		return [
			'keywords' => $keywords,
			'match_mode' => $matchMode,
			'keywords_title' => $keywordsTitle,
			'keywords_feed' => $keywordsFeed,
			'keywords_authors' => $keywordsAuthors,
			'keywords_content' => $keywordsContent,
			'search_in_title' => Minz_Request::paramBoolean('search_in_title'),
			'search_in_feed' => Minz_Request::paramBoolean('search_in_feed'),
			'search_in_authors' => Minz_Request::paramBoolean('search_in_authors'),
			'search_in_content' => Minz_Request::paramBoolean('search_in_content'),
			'mark_as_read' => Minz_Request::paramBoolean('mark_as_read'),
			'ignore_updated' => Minz_Request::paramBoolean('ignore_updated'),
			'webhook_url' => trim(Minz_Request::paramString('webhook_url')),
			'webhook_method' => ($methodValue ?? self::DEFAULT_METHOD)->value,
			'webhook_headers' => $headers,
			'webhook_body' => html_entity_decode(Minz_Request::paramString('webhook_body'), ENT_QUOTES | ENT_HTML5),
			'webhook_body_type' => ($bodyTypeValue ?? self::DEFAULT_BODY_TYPE)->value,
			'enable_logging' => Minz_Request::paramBoolean('enable_logging'),
		];
	}

	private function shouldSendTestRequest(): bool {
		return Minz_Request::paramBoolean('test_request');
	}

	/**
	 * Return the configuration snapshot for the current user.
	 *
	 * @return array{
	 *   keywords: list<string>,
	 *   match_mode: 'basic'|'advanced',
	 *   keywords_title: list<string>,
	 *   keywords_feed: list<string>,
	 *   keywords_authors: list<string>,
	 *   keywords_content: list<string>,
	 *   search_in_title: bool,
	 *   search_in_feed: bool,
	 *   search_in_authors: bool,
	 *   search_in_content: bool,
	 *   mark_as_read: bool,
	 *   ignore_updated: bool,
	 *   webhook_headers: list<string>,
	 *   webhook_url: string,
	 *   webhook_method: string,
	 *   webhook_body: string,
	 *   webhook_body_type: string,
	 *   enable_logging: bool
	 * }|null
	 */
	private function getSnapshot(): ?array {
		$userConf = $this->getUserConf();
		if ($userConf === null) {
			return null;
		}

		return [
			'keywords' => $this->getArrayAttribute($userConf, 'keywords', []),
			'match_mode' => $this->normalizeMatchMode($userConf->attributeString('match_mode')),
			'keywords_title' => $this->getArrayAttribute($userConf, 'keywords_title', []),
			'keywords_feed' => $this->getArrayAttribute($userConf, 'keywords_feed', []),
			'keywords_authors' => $this->getArrayAttribute($userConf, 'keywords_authors', []),
			'keywords_content' => $this->getArrayAttribute($userConf, 'keywords_content', []),
			'search_in_title' => $this->getBoolAttribute($userConf, 'search_in_title', true),
			'search_in_feed' => $this->getBoolAttribute($userConf, 'search_in_feed', false),
			'search_in_authors' => $this->getBoolAttribute($userConf, 'search_in_authors', false),
			'search_in_content' => $this->getBoolAttribute($userConf, 'search_in_content', false),
			'mark_as_read' => $this->getBoolAttribute($userConf, 'mark_as_read', false),
			'ignore_updated' => $this->getBoolAttribute($userConf, 'ignore_updated', false),
			'webhook_headers' => $this->getArrayAttribute($userConf, 'webhook_headers', self::DEFAULT_HEADERS),
			'webhook_url' => $this->getStringAttribute($userConf, 'webhook_url', self::DEFAULT_URL),
			'webhook_method' => $this->normalizeMethodValue($userConf->attributeString('webhook_method')),
			'webhook_body' => $this->getStringAttribute($userConf, 'webhook_body', self::DEFAULT_BODY_TEMPLATE),
			'webhook_body_type' => $this->normalizeBodyTypeValue($userConf->attributeString('webhook_body_type')),
			'enable_logging' => $this->getBoolAttribute($userConf, 'enable_logging', false),
		];
	}

	private function normalizeMethodValue(?string $method): string {
		$methodValue = $method ?? '';
		return (HTTP_METHOD::tryFrom(strtoupper($methodValue)) ?? self::DEFAULT_METHOD)->value;
	}

	private function normalizeBodyTypeValue(?string $bodyType): string {
		$bodyTypeValue = $bodyType ?? '';
		return (BODY_TYPE::tryFrom(strtolower($bodyTypeValue)) ?? self::DEFAULT_BODY_TYPE)->value;
	}

	/**
	 * @return 'basic'|'advanced'
	 */
	private function normalizeMatchMode(?string $matchMode): string {
		if ($matchMode === self::MATCH_MODE_ADVANCED) {
			return self::MATCH_MODE_ADVANCED;
		}

		return self::MATCH_MODE_BASIC;
	}

	/**
	 * @param non-empty-string $key
	 * @param list<string> $default
	 * @return list<string>
	 */
	private function getArrayAttribute(FreshRSS_UserConfiguration $userConf, string $key, array $default): array {
		$value = $userConf->attributeArray($key);
		if ($value === null) {
			return $default;
		}

		$normalized = [];
		foreach ($value as $item) {
			$trimmed = trim($this->normalizeScalarToString($item));
			if ($trimmed !== '') {
				$normalized[] = $trimmed;
			}
		}

		return $normalized;
	}

	/** @param non-empty-string $key */
	private function getBoolAttribute(FreshRSS_UserConfiguration $userConf, string $key, bool $default): bool {
		$value = $userConf->attributeBool($key);
		return $value ?? $default;
	}

	/** @param non-empty-string $key */
	private function getStringAttribute(FreshRSS_UserConfiguration $userConf, string $key, string $default): string {
		$value = $userConf->attributeString($key);
		return ($value === null || $value === '') ? $default : $value;
	}

	/**
	 * Normalize a list input (textarea) into trimmed values.
	 *
	 * @param array<int|string, string>|null $values
	 * @return list<string>
	 */
	private function normalizeListInput(?array $values): array {
		if (!is_array($values)) {
			return [];
		}

		$result = [];
		foreach ($values as $value) {
			$trimmed = trim((string) $value);
			if ($trimmed !== '') {
				$result[] = $trimmed;
			}
		}

		return $result;
	}

	private function normalizePattern(string $pattern): ?string {
		$pattern = trim($pattern);
		if ($pattern === '') {
			return null;
		}

		if ($pattern[0] === '/' && strrpos($pattern, '/', 1) !== false) {
			return $pattern;
		}

		return '/' . preg_quote($pattern, '/') . '/i';
	}

	private function isPatternFound(string $pattern, string $text, string $fallback): bool {
		if ($pattern === '' || $text === '') {
			return false;
		}

		$result = @preg_match($pattern, $text);
		if ($result === 1) {
			return true;
		}

		if ($result === false) {
			logError($this->logsEnabled, 'Invalid regex pattern: ' . $pattern);
		}

		$fallbackNeedle = $fallback !== '' ? $fallback : $pattern;
		return str_contains($text, $fallbackNeedle);
	}

	private function getEntryThumbnail(FreshRSS_Entry $entry): string {
		$thumbnail = $entry->thumbnail();
		if ($thumbnail !== null && $thumbnail['url'] !== '') {
			return $thumbnail['url'];
		}

		$enclosures = $entry->enclosures();
		foreach ($enclosures as $enclosure) {
			$url = $this->extractEnclosureUrl($enclosure);
			if ($url !== '') {
				return $url;
			}
		}

		return '';
	}

	private function getPlainTextContent(FreshRSS_Entry $entry): string {
		$content = $entry->content();
		if ($content === '') {
			return '';
		}

		$text = strip_tags($content);
		$text = html_entity_decode($text, ENT_QUOTES | ENT_HTML5, 'UTF-8');
		$text = preg_replace('/\s+/u', ' ', $text) ?? '';
		$text = trim($text);

		if ($text === '') {
			return '';
		}

		if (function_exists('mb_strlen') && function_exists('mb_substr')) {
			if (mb_strlen($text) > self::PLAINTEXT_MAX_LENGTH) {
				return rtrim(mb_substr($text, 0, self::PLAINTEXT_MAX_LENGTH - 1)) . '…';
			}
			return $text;
		}

		if (strlen($text) > self::PLAINTEXT_MAX_LENGTH) {
			return rtrim(substr($text, 0, self::PLAINTEXT_MAX_LENGTH - 1)) . '…';
		}

		return $text;
	}

	private function extractEnclosureUrl(mixed $enclosure): string {
		$url = $this->getEnclosureValue($enclosure, 'url');
		if ($url === '') {
			return '';
		}

		$type = $this->getEnclosureValue($enclosure, 'type');
		if ($type === '' || stripos($type, 'image/') === 0) {
			return $url;
		}

		return '';
	}

	private function getEnclosureValue(mixed $enclosure, string $name): string {
		if (is_array($enclosure)) {
			if (!array_key_exists($name, $enclosure)) {
				return '';
			}
			return $this->normalizeScalarToString($enclosure[$name]);
		}

		if (!is_object($enclosure)) {
			return '';
		}

		if ($name === 'url') {
			if (method_exists($enclosure, 'get_link')) {
				return $this->normalizeScalarToString($enclosure->get_link());
			}
			if (method_exists($enclosure, 'link')) {
				return $this->normalizeScalarToString($enclosure->link());
			}
		}

		if ($name === 'type') {
			if (method_exists($enclosure, 'get_type')) {
				return $this->normalizeScalarToString($enclosure->get_type());
			}
			if (method_exists($enclosure, 'type')) {
				return $this->normalizeScalarToString($enclosure->type());
			}
		}

		return '';
	}

	public function getKeywordsData(): string {
		$config = $this->getSnapshot();
		if ($config === null) {
			return '';
		}

		return implode(PHP_EOL, $config['keywords']);
	}

	public function getKeywordDataByField(string $field): string {
		$config = $this->getSnapshot();
		if ($config === null) {
			return '';
		}

		return match ($field) {
			'title' => implode(PHP_EOL, $config['keywords_title']),
			'feed' => implode(PHP_EOL, $config['keywords_feed']),
			'authors' => implode(PHP_EOL, $config['keywords_authors']),
			'content' => implode(PHP_EOL, $config['keywords_content']),
			default => '',
		};
	}

	public function getMatchMode(): string {
		$config = $this->getSnapshot();
		return $config === null ? self::MATCH_MODE_BASIC : $config['match_mode'];
	}

	public function getWebhookHeaders(): string {
		$config = $this->getSnapshot();
		if ($config === null) {
			return implode(PHP_EOL, self::DEFAULT_HEADERS);
		}

		return implode(PHP_EOL, $config['webhook_headers']);
	}

	public function getWebhookUrl(): string {
		$config = $this->getSnapshot();
		return $config === null ? self::DEFAULT_URL : $config['webhook_url'];
	}

	public function getWebhookBody(): string {
		$config = $this->getSnapshot();
		return $config === null ? self::DEFAULT_BODY_TEMPLATE : $config['webhook_body'];
	}

	public function getWebhookBodyType(): string {
		$config = $this->getSnapshot();
		return $config === null ? self::DEFAULT_BODY_TYPE->value : $config['webhook_body_type'];
	}
}

function _LOG(bool $logEnabled, mixed $data): void {
	logWarning($logEnabled, $data);
}

function _LOG_ERR(bool $logEnabled, mixed $data): void {
	logError($logEnabled, $data);
}
