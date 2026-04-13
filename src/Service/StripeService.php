<?php

namespace App\Service;

class StripeService
{
    public function __construct(
        private readonly string $secretKey,
        private readonly string $webhookSecret,
    ) {
    }

    public function createPaymentIntent(
        int $amountInCents,
        string $currency = 'eur',
        array $metadata = [],
    ): array {
        $formPayload = [
            'amount' => $amountInCents,
            'currency' => $currency,
            'automatic_payment_methods[enabled]' => 'true',
        ];

        foreach ($metadata as $key => $value) {
            $formPayload[sprintf('metadata[%s]', $key)] = $value;
        }

        $curl = curl_init('https://api.stripe.com/v1/payment_intents');
        if ($curl === false) {
            throw new \RuntimeException('Unable to initialize Stripe request');
        }

        curl_setopt_array($curl, [
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS => http_build_query($formPayload),
            CURLOPT_HTTPHEADER => [
                'Authorization: Bearer ' . $this->secretKey,
                'Content-Type: application/x-www-form-urlencoded',
            ],
        ]);

        $rawResponse = curl_exec($curl);
        if ($rawResponse === false) {
            $error = curl_error($curl);
            curl_close($curl);

            throw new \RuntimeException($error);
        }

        $statusCode = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        $decodedResponse = json_decode($rawResponse, true);
        if (!is_array($decodedResponse)) {
            throw new \UnexpectedValueException('Invalid Stripe API response');
        }

        if ($statusCode >= 400) {
            $errorMessage = $decodedResponse['error']['message'] ?? 'Stripe API error';
            throw new \RuntimeException((string) $errorMessage);
        }

        return $decodedResponse;
    }

    public function constructWebhookEvent(string $payload, string $signatureHeader): array
    {
        $headerParts = [];
        foreach (explode(',', $signatureHeader) as $chunk) {
            [$key, $value] = array_pad(explode('=', trim($chunk), 2), 2, null);
            if ($key !== null && $value !== null) {
                $headerParts[$key][] = $value;
            }
        }

        $timestamp = $headerParts['t'][0] ?? null;
        $signatures = $headerParts['v1'] ?? [];
        if (!is_string($timestamp) || $timestamp === '' || $signatures === []) {
            throw new \UnexpectedValueException('Invalid Stripe-Signature header');
        }

        $signedPayload = $timestamp . '.' . $payload;
        $expectedSignature = hash_hmac('sha256', $signedPayload, $this->webhookSecret);

        $isValid = false;
        foreach ($signatures as $signature) {
            if (hash_equals($expectedSignature, $signature)) {
                $isValid = true;
                break;
            }
        }

        if (!$isValid) {
            throw new \UnexpectedValueException('Invalid Stripe signature');
        }

        $decodedPayload = json_decode($payload, true);
        if (!is_array($decodedPayload)) {
            throw new \UnexpectedValueException('Invalid Stripe payload');
        }

        return $decodedPayload;
    }
}
