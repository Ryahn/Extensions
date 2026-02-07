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
 * @author Lukas Melega, Ryahn
 * @version 0.2.0
 * @since FreshRSS 1.20.0
 */
final class WebhookExtension extends Minz_Extension {
	private const DEFAULT_URL = 'http://<WRITE YOUR URL HERE>';
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
	private const JSON_LOG_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

	private bool $logsEnabled = false;

	#[\Override]
	public function init(): void {
		$this->registerTranslates();
		$this->ensureConfigurationDefaults();
		$this->registerHook('entry_before_insert', [$this, 'processArticle']);
	}

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

		$this->logsEnabled = (bool) ($config['enable_logging'] ?? false);

		$loggable = $config;
		$loggable['webhook_body'] = '[redacted]';
		logWarning(
			$this->logsEnabled,
			'Webhook configuration saved: ' . json_encode($loggable, self::JSON_LOG_FLAGS)
		);

		if ($this->shouldSendTestRequest()) {
			try {
				$this->sendTestRequest($config);
			} catch (Throwable $err) {
				logError($this->logsEnabled, 'Test webhook request failed: ' . $err->getMessage());
			}
		}
	}

	/**
	 * Process article and send webhook if patterns match.
	 *
	 * @param FreshRSS_Entry|mixed $entry
	 */
	public function processArticle($entry): FreshRSS_Entry {
		if (!$entry instanceof FreshRSS_Entry) {
			return $entry;
		}

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

		$patterns = $config['keywords'];
		if ($patterns === []) {
			logWarning($this->logsEnabled, 'No keywords defined in Webhook extension settings.');
			return $entry;
		}

		$matchLog = $this->findMatchLog($entry, $patterns, $config);
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
	 * Try to find a pattern that matches this entry.
	 *
	 * @param array<int, string> $patterns
	 * @param array<string, mixed> $config
	 */
	private function findMatchLog(FreshRSS_Entry $entry, array $patterns, array $config): ?string {
		$title = (string) $entry->title();
		$link = (string) $entry->link();
		$feed = $entry->feed();
		$feedName = (is_object($feed) && method_exists($feed, 'name')) ? (string) $feed->name() : '';
		$authors = trim((string) $entry->authors(true));
		$content = (string) $entry->content();

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
	 * Send article data via webhook.
	 *
	 * @param array<string, mixed> $config
	 */
	private function sendArticle(FreshRSS_Entry $entry, string $additionalLog, array $config): void {
		try {
			$bodyTemplate = (string) $config['webhook_body'];
			$replacements = $this->buildReplacements($entry);
			$body = str_replace(array_keys($replacements), array_values($replacements), $bodyTemplate);

			sendReq(
				(string) $config['webhook_url'],
				(string) $config['webhook_method'],
				(string) $config['webhook_body_type'],
				$body,
				$config['webhook_headers'],
				(bool) $config['enable_logging'],
				$additionalLog,
			);
		} catch (Throwable $err) {
			logError($this->logsEnabled, 'sendArticle error: ' . $err->getMessage());
		}
	}

	/**
	 * Send a manual test request using configuration data.
	 *
	 * @param array<string, mixed> $config
	 */
	private function sendTestRequest(array $config): void {
		sendReq(
			(string) $config['webhook_url'],
			(string) $config['webhook_method'],
			(string) $config['webhook_body_type'],
			(string) $config['webhook_body'],
			$config['webhook_headers'],
			(bool) $config['enable_logging'],
			'Test request from configuration',
		);
	}

	/**
	 * Build placeholder replacements for the configured template.
	 *
	 * @return array<string, string>
	 */
	private function buildReplacements(FreshRSS_Entry $entry): array {
		$feed = $entry->feed();
		$feedName = (is_object($feed) && method_exists($feed, 'name')) ? (string) $feed->name() : '';

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
			$value = implode(', ', array_map(static fn ($item): string => (string) $item, $value));
		} elseif (is_object($value)) {
			if (method_exists($value, '__toString')) {
				$value = (string) $value;
			} else {
				return '';
			}
		}

		$string = html_entity_decode((string) $value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
		$string = preg_replace('/\s+/u', ' ', $string) ?? '';

		return addcslashes(trim($string), "\"\\");
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
		if (!method_exists($this, 'getSystemConfiguration')) {
			return false;
		}

		$legacy = $this->getSystemConfiguration();
		if (!is_array($legacy) || $legacy === []) {
			return false;
		}

		$needsSave = false;
		$map = [
			'keywords' => ['type' => 'array'],
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
		return match ($type) {
			'array' => $userConf->attributeArray($key) !== null,
			'bool' => $userConf->attributeBool($key) !== null,
			default => $userConf->attributeString($key) !== null,
		};
	}

	private function ensureBoolDefault(FreshRSS_UserConfiguration $userConf, string $key, bool $default): bool {
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
	 * @return array<string, mixed>
	 */
	private function collectConfigurationFromRequest(): array {
		$keywords = $this->normalizeListInput(Minz_Request::paramTextToArray('keywords'));
		$headers = $this->normalizeListInput(Minz_Request::paramTextToArray('webhook_headers'));
		$headers = $headers === [] ? self::DEFAULT_HEADERS : $headers;

		$methodValue = HTTP_METHOD::tryFrom(strtoupper(Minz_Request::paramString('webhook_method')));
		$bodyTypeValue = BODY_TYPE::tryFrom(strtolower(Minz_Request::paramString('webhook_body_type')));

		return [
			'keywords' => $keywords,
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
	 * @return array<string, mixed>|null
	 */
	private function getSnapshot(): ?array {
		$userConf = $this->getUserConf();
		if ($userConf === null) {
			return null;
		}

		return [
			'keywords' => $this->getArrayAttribute($userConf, 'keywords', []),
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
		return (HTTP_METHOD::tryFrom(strtoupper((string) $method)) ?? self::DEFAULT_METHOD)->value;
	}

	private function normalizeBodyTypeValue(?string $bodyType): string {
		return (BODY_TYPE::tryFrom(strtolower((string) $bodyType)) ?? self::DEFAULT_BODY_TYPE)->value;
	}

	/**
	 * @return string[]
	 */
	private function getArrayAttribute(FreshRSS_UserConfiguration $userConf, string $key, array $default): array {
		$value = $userConf->attributeArray($key);
		if (!is_array($value)) {
			return $default;
		}

		$normalized = [];
		foreach ($value as $item) {
			$trimmed = trim((string) $item);
			if ($trimmed !== '') {
				$normalized[] = $trimmed;
			}
		}

		return $normalized;
	}

	private function getBoolAttribute(FreshRSS_UserConfiguration $userConf, string $key, bool $default): bool {
		$value = $userConf->attributeBool($key);
		return $value ?? $default;
	}

	private function getStringAttribute(FreshRSS_UserConfiguration $userConf, string $key, string $default): string {
		$value = $userConf->attributeString($key);
		return ($value === null || $value === '') ? $default : $value;
	}

	/**
	 * Normalize a list input (textarea) into trimmed values.
	 *
	 * @param array<int|string, string>|null $values
	 * @return string[]
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
		return $fallbackNeedle !== '' && str_contains($text, $fallbackNeedle);
	}

	private function getEntryThumbnail(FreshRSS_Entry $entry): string {
		if (method_exists($entry, 'thumbnail')) {
			$thumbnail = $entry->thumbnail();
			if (is_string($thumbnail) && $thumbnail !== '') {
				return $thumbnail;
			}
		}

		if (method_exists($entry, 'enclosures')) {
			$enclosures = $entry->enclosures();
			if (is_array($enclosures)) {
				foreach ($enclosures as $enclosure) {
					$url = $this->extractEnclosureUrl($enclosure);
					if ($url !== '') {
						return $url;
					}
				}
			}
		}

		return '';
	}

	private function extractEnclosureUrl(mixed $enclosure): string {
		if (!is_object($enclosure)) {
			return '';
		}

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

	private function getEnclosureValue(object $enclosure, string $name): string {
		if (method_exists($enclosure, $name)) {
			$value = $enclosure->{$name}();
			return is_string($value) ? $value : (string) $value;
		}

		if (isset($enclosure->{$name})) {
			$value = $enclosure->{$name};
			return is_string($value) ? $value : (string) $value;
		}

		return '';
	}

	public function getKeywordsData(): string {
		$config = $this->getSnapshot();
		$keywords = $config['keywords'] ?? [];
		return implode(PHP_EOL, $keywords);
	}

	public function getWebhookHeaders(): string {
		$config = $this->getSnapshot();
		$headers = $config['webhook_headers'] ?? self::DEFAULT_HEADERS;
		return implode(PHP_EOL, $headers);
	}

	public function getWebhookUrl(): string {
		$config = $this->getSnapshot();
		return $config['webhook_url'] ?? self::DEFAULT_URL;
	}

	public function getWebhookBody(): string {
		$config = $this->getSnapshot();
		return $config['webhook_body'] ?? self::DEFAULT_BODY_TEMPLATE;
	}

	public function getWebhookBodyType(): string {
		$config = $this->getSnapshot();
		return $config['webhook_body_type'] ?? self::DEFAULT_BODY_TYPE->value;
	}
}

function _LOG(bool $logEnabled, $data): void {
	logWarning($logEnabled, $data);
}

function _LOG_ERR(bool $logEnabled, $data): void {
	logError($logEnabled, $data);
}
