import { sign, SIGNATURE_AGENT_HEADER } from 'web-bot-auth';
import { signerFromJWK } from 'web-bot-auth/crypto';

export default {
	async fetch(request, _env, _ctx): Promise<Response> {
		// hardcoded key - bring your own!
		const wba_jwk = {
			kty: 'OKP',
			crv: 'Ed25519',
			x: '2TXotAGP3Aev7jxkiYZq_6oqpDg_r4OQS-ocFkdq8B4',
			d: 'ToJ_oAIupe-7gDv64XYhdUsG-GZmhKh2VQGqKiLqoe8',
		};
		const signer = await signerFromJWK(wba_jwk);
		const now = new Date();

		const modifiedRequest = new Request(request);
		modifiedRequest.headers.set(
			SIGNATURE_AGENT_HEADER,
			'sig1="https://www.example.com/.well-known/http-message-signatures-directory";type=directory',
		);

		const fields = await sign(modifiedRequest, {
			signer,
			created: now,
			expires: new Date(now.getTime() + 300_000),
		});

		modifiedRequest.headers.set('Signature', fields.signature);
		modifiedRequest.headers.set('Signature-Input', fields.signatureInput);

		return fetch(modifiedRequest);
	},
} satisfies ExportedHandler<Env>;
