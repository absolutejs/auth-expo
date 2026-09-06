import { describe, expect, mock, test } from 'bun:test';
import { MobileAuthError } from '@absolutejs/auth/client/mobile';
import type { AbsoluteExpoAuthDependencies } from '../src';

mock.module('react-native', () => ({
	AppState: { addEventListener: () => ({ remove: () => undefined }) }
}));
mock.module('expo-linking', () => ({
	addEventListener: () => ({ remove: () => undefined }),
	getInitialURL: async () => null
}));
mock.module('expo-secure-store', () => ({
	AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: 1,
	deleteItemAsync: async () => undefined,
	getItemAsync: async () => null,
	isAvailableAsync: async () => true,
	setItemAsync: async () => undefined
}));
mock.module('expo-web-browser', () => ({
	openAuthSessionAsync: async () => ({ type: 'cancel' })
}));
mock.module('expo-crypto', () => ({
	CryptoDigestAlgorithm: { SHA256: 'SHA-256' },
	digest: (algorithm: AlgorithmIdentifier, value: Uint8Array) =>
		crypto.subtle.digest(algorithm, new Uint8Array(value)),
	getRandomBytes: (length: number) =>
		crypto.getRandomValues(new Uint8Array(length))
}));

const { absoluteExpoAuthCrypto, createAbsoluteExpoAuthAdapters } = await import(
	'../src'
);

const fixture = () => {
	const values = new Map<string, string>();
	const linkListeners = new Set<(event: { url: string }) => void>();
	const stateListeners = new Set<(state: string) => void>();
	const options: Record<string, unknown>[] = [];
	let browserResult: { type: string; url?: string } = { type: 'cancel' };
	const dependencies: AbsoluteExpoAuthDependencies = {
		appState: {
			addEventListener: (_type, listener) => {
				stateListeners.add(listener);

				return { remove: () => stateListeners.delete(listener) };
			}
		},
		linking: {
			addEventListener: (_type, listener) => {
				linkListeners.add(listener);

				return { remove: () => linkListeners.delete(listener) };
			},
			getInitialURL: async () => 'product://cold'
		},
		secureStore: {
			AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: 7,
			deleteItemAsync: async (key, value) => {
				options.push(value ?? {});
				values.delete(key);
			},
			getItemAsync: async (key, value) => {
				options.push(value ?? {});

				return values.get(key) ?? null;
			},
			isAvailableAsync: async () => true,
			setItemAsync: async (key, value, setting) => {
				options.push(setting ?? {});
				values.set(key, value);
			}
		},
		webBrowser: {
			openAuthSessionAsync: async () => browserResult
		}
	};

	return {
		dependencies,
		emitLink: (url: string) =>
			linkListeners.forEach((listener) => listener({ url })),
		emitState: (state: string) =>
			stateListeners.forEach((listener) => listener(state)),
		options,
		setBrowserResult: (result: typeof browserResult) => {
			browserResult = result;
		},
		values
	};
};

describe('AbsoluteJS Expo Auth adapters', () => {
	test('provides native PKCE primitives and verifies JOSE ES256 signatures', async () => {
		const pair = await crypto.subtle.generateKey(
			{ name: 'ECDSA', namedCurve: 'P-256' },
			true,
			['sign', 'verify']
		);
		const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
		const data = new TextEncoder().encode('absolutejs-expo-auth');
		const signature = new Uint8Array(
			await crypto.subtle.sign(
				{ hash: 'SHA-256', name: 'ECDSA' },
				pair.privateKey,
				data
			)
		);
		expect(absoluteExpoAuthCrypto.randomBytes(32)).toHaveLength(32);
		expect(await absoluteExpoAuthCrypto.digestSha256(data)).toHaveLength(
			32
		);
		expect(
			await absoluteExpoAuthCrypto.verifyEs256({ data, jwk, signature })
		).toBe(true);
		signature[0] ^= 1;
		expect(
			await absoluteExpoAuthCrypto.verifyEs256({ data, jwk, signature })
		).toBe(false);
	});

	test('namespaces credentials and uses device-only after-first-unlock storage', async () => {
		const value = fixture();
		const { storage } = createAbsoluteExpoAuthAdapters(
			{
				redirectUri: 'product://auth/callback',
				storagePrefix: 'product.auth'
			},
			value.dependencies
		);
		await storage.set('oidc.refresh', 'secret');
		expect(await storage.get('oidc.refresh')).toBe('secret');
		expect(value.values.get('product.auth.oidc.refresh')).toBe('secret');
		expect(value.options).toEqual([
			{ keychainAccessible: 7 },
			{ keychainAccessible: 7 }
		]);
		await storage.remove('oidc.refresh');
		expect(await storage.capability?.()).toEqual({ available: true });
	});

	test('delivers warm and auth-session callbacks exactly once', async () => {
		const value = fixture();
		const { links } = createAbsoluteExpoAuthAdapters(
			{ redirectUri: 'product://auth/callback' },
			value.dependencies
		);
		const received: string[] = [];
		const stop = await links.onOpen((url) => received.push(url));
		value.setBrowserResult({
			type: 'success',
			url: 'product://auth/callback?code=one'
		});
		await links.openExternal('https://issuer.example/authorize');
		await Bun.sleep(1_100);
		value.emitLink('product://auth/callback?code=one');
		await Promise.resolve();
		expect(received).toEqual(['product://auth/callback?code=one']);
		expect(await links.getLaunchUrl()).toBe('product://cold');
		await stop();
	});

	test('rejects browser cancellation instead of leaving sign-in pending', async () => {
		const value = fixture();
		const { links } = createAbsoluteExpoAuthAdapters(
			{ redirectUri: 'product://auth/callback' },
			value.dependencies
		);
		expect(
			links.openExternal('https://issuer.example/authorize')
		).rejects.toMatchObject({
			code: 'aborted'
		} satisfies Partial<MobileAuthError>);
	});

	test('bounds a native initial-link lookup that never settles', async () => {
		const value = fixture();
		value.dependencies.linking.getInitialURL = () => new Promise(() => {});
		const { links } = createAbsoluteExpoAuthAdapters(
			{
				launchUrlTimeoutMs: 1,
				redirectUri: 'product://auth/callback'
			},
			value.dependencies
		);
		expect(await links.getLaunchUrl()).toBeNull();
	});

	test('refreshes only when the app resumes from a non-active state', async () => {
		const value = fixture();
		const { lifecycle } = createAbsoluteExpoAuthAdapters(
			{ redirectUri: 'product://auth/callback' },
			value.dependencies
		);
		let resumes = 0;
		const stop = await lifecycle.onResume?.(() => {
			resumes += 1;
		});
		value.emitState('active');
		value.emitState('background');
		value.emitState('active');
		value.emitState('active');
		expect(resumes).toBe(1);
		await stop?.();
	});

	test('serializes refresh-token work inside the native JS runtime', async () => {
		const value = fixture();
		const { storage } = createAbsoluteExpoAuthAdapters(
			{ redirectUri: 'product://auth/callback' },
			value.dependencies
		);
		const events: string[] = [];
		let release!: () => void;
		const blocked = new Promise<void>((resolve) => {
			release = resolve;
		});
		const first = storage.withLock?.('oidc.refresh', async () => {
			events.push('first-start');
			await blocked;
			events.push('first-end');
		});
		const second = storage.withLock?.('oidc.refresh', async () => {
			events.push('second');
		});
		await Promise.resolve();
		expect(events).toEqual(['first-start']);
		release();
		await Promise.all([first, second]);
		expect(events).toEqual(['first-start', 'first-end', 'second']);
	});
});
