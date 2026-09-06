import {
	createMobileAuthClient,
	MobileAuthError,
	type MobileAuthClientConfig,
	type MobileAuthCrypto,
	type MobileAuthLifecycle,
	type MobileAuthLinks,
	type MobileAuthSecureStorage
} from '@absolutejs/auth/client/mobile';
import { p256 } from '@noble/curves/nist.js';
import * as Crypto from 'expo-crypto';
import * as Linking from 'expo-linking';
import * as SecureStore from 'expo-secure-store';
import * as WebBrowser from 'expo-web-browser';
import { AppState } from 'react-native';

type LinkSubscription = { remove(): void };
type AppStateSubscription = { remove(): void };

const MAX_DELIVERED_CALLBACKS = 32;

export type AbsoluteExpoAuthDependencies = {
	appState: {
		addEventListener(
			type: 'change',
			listener: (state: string) => void
		): AppStateSubscription;
	};
	linking: {
		addEventListener(
			type: 'url',
			listener: (event: { url: string }) => void
		): LinkSubscription;
		getInitialURL(): Promise<string | null>;
	};
	secureStore: {
		AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: number;
		deleteItemAsync(
			key: string,
			options?: Record<string, unknown>
		): Promise<void>;
		getItemAsync(
			key: string,
			options?: Record<string, unknown>
		): Promise<string | null>;
		isAvailableAsync(): Promise<boolean>;
		setItemAsync(
			key: string,
			value: string,
			options?: Record<string, unknown>
		): Promise<void>;
	};
	webBrowser: {
		openAuthSessionAsync(
			url: string,
			redirectUrl: string
		): Promise<{ type: string; url?: string }>;
	};
};

export type AbsoluteExpoAuthAdapterOptions = {
	redirectUri: string;
	storagePrefix?: string;
};

export type AbsoluteExpoAuthClientConfig = Omit<
	MobileAuthClientConfig,
	'lifecycle' | 'links' | 'storage'
> & {
	storagePrefix?: string;
};

const defaultDependencies = (): AbsoluteExpoAuthDependencies => ({
	appState: AppState,
	linking: Linking,
	secureStore: SecureStore,
	webBrowser: WebBrowser
});

const normalizeStoragePrefix = (value = 'absolutejs.auth') => {
	if (!/^[A-Za-z0-9._-]{1,80}$/u.test(value))
		throw new TypeError(
			'Expo Auth storagePrefix must use 1-80 letters, numbers, dots, underscores, or hyphens.'
		);

	return value;
};

const decodeBase64Url = (value: string) => {
	const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
	const padded = normalized.padEnd(
		normalized.length + ((4 - (normalized.length % 4)) % 4),
		'='
	);
	const binary = atob(padded);

	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

export const absoluteExpoAuthCrypto: MobileAuthCrypto = {
	digestSha256: async (value) =>
		new Uint8Array(
			await Crypto.digest(
				Crypto.CryptoDigestAlgorithm.SHA256,
				new Uint8Array(value)
			)
		),
	randomBytes: (length) => Crypto.getRandomBytes(length),
	verifyEs256: async ({ data, jwk, signature }) => {
		if (
			jwk.kty !== 'EC' ||
			jwk.crv !== 'P-256' ||
			typeof jwk.x !== 'string' ||
			typeof jwk.y !== 'string'
		)
			return false;
		const x = decodeBase64Url(jwk.x);
		const y = decodeBase64Url(jwk.y);
		if (x.length !== 32 || y.length !== 32 || signature.length !== 64)
			return false;
		const publicKey = new Uint8Array(65);
		publicKey[0] = 4;
		publicKey.set(x, 1);
		publicKey.set(y, 33);

		return p256.verify(signature, data, publicKey, {
			format: 'compact',
			lowS: false,
			prehash: true
		});
	}
};

const lockTails = new Map<string, Promise<void>>();

const withProcessLock = async <T>(key: string, run: () => Promise<T>) => {
	const previous = lockTails.get(key) ?? Promise.resolve();
	let release: () => void = () => undefined;
	const current = new Promise<void>((resolve) => {
		release = resolve;
	});
	const tail = previous.then(() => current);
	lockTails.set(key, tail);
	await previous;
	try {
		return await run();
	} finally {
		release();
		if (lockTails.get(key) === tail) lockTails.delete(key);
	}
};

export const createAbsoluteExpoAuthAdapters = (
	options: AbsoluteExpoAuthAdapterOptions,
	dependencies: AbsoluteExpoAuthDependencies = defaultDependencies()
): {
	lifecycle: MobileAuthLifecycle;
	links: MobileAuthLinks;
	storage: MobileAuthSecureStorage;
} => {
	const prefix = normalizeStoragePrefix(options.storagePrefix);
	const keyFor = (key: string) => `${prefix}.${key}`;
	const secureStoreOptions = {
		keychainAccessible:
			dependencies.secureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY
	};
	const listeners = new Set<(url: string) => void>();
	const deliveredUrls = new Set<string>();
	const deliver = (url: string) => {
		if (deliveredUrls.has(url)) return;
		deliveredUrls.add(url);
		if (deliveredUrls.size > MAX_DELIVERED_CALLBACKS) {
			const oldest = deliveredUrls.values().next().value;
			if (typeof oldest === 'string') deliveredUrls.delete(oldest);
		}
		for (const listener of listeners) listener(url);
	};

	return {
		lifecycle: {
			onResume: async (listener) => {
				let previous: string | undefined;
				const subscription = dependencies.appState.addEventListener(
					'change',
					(state) => {
						if (
							state === 'active' &&
							previous &&
							previous !== 'active'
						)
							listener();
						previous = state;
					}
				);

				return () => subscription.remove();
			}
		},
		links: {
			getLaunchUrl: () => dependencies.linking.getInitialURL(),
			onOpen: async (listener) => {
				listeners.add(listener);
				const subscription = dependencies.linking.addEventListener(
					'url',
					({ url }) => deliver(url)
				);

				return () => {
					listeners.delete(listener);
					subscription.remove();
				};
			},
			openExternal: async (url) => {
				const result =
					await dependencies.webBrowser.openAuthSessionAsync(
						url,
						options.redirectUri
					);
				if (result.type === 'success' && result.url) {
					deliver(result.url);

					return;
				}
				throw new MobileAuthError(
					'aborted',
					'Authorization was cancelled.'
				);
			}
		},
		storage: {
			capability: async () => {
				const available =
					await dependencies.secureStore.isAvailableAsync();

				return available
					? { available: true }
					: {
							available: false,
							message:
								'Expo SecureStore is unavailable on this device.'
						};
			},
			get: (key) =>
				dependencies.secureStore.getItemAsync(
					keyFor(key),
					secureStoreOptions
				),
			remove: (key) =>
				dependencies.secureStore.deleteItemAsync(
					keyFor(key),
					secureStoreOptions
				),
			set: (key, value) =>
				dependencies.secureStore.setItemAsync(
					keyFor(key),
					value,
					secureStoreOptions
				),
			withLock: (key, run) => withProcessLock(keyFor(key), run)
		}
	};
};

export const createAbsoluteExpoAuthClient = (
	config: AbsoluteExpoAuthClientConfig,
	dependencies?: AbsoluteExpoAuthDependencies
) => {
	const { storagePrefix, ...mobileConfig } = config;
	const adapters = createAbsoluteExpoAuthAdapters(
		{
			redirectUri: config.redirectUri,
			...(storagePrefix ? { storagePrefix } : {})
		},
		dependencies
	);

	return createMobileAuthClient({
		crypto: absoluteExpoAuthCrypto,
		...mobileConfig,
		...adapters
	});
};
