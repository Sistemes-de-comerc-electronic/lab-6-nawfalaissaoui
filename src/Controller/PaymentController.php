<?php

namespace App\Controller;

use App\Service\StripeService;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTDecodeFailureException;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Annotation\Route;

class PaymentController extends AbstractController
{
    private const FIXED_AMOUNT_EUR = 20;
    private const FIXED_AMOUNT_CENTS = 2000;

    public function __construct(
        private readonly StripeService $stripeService,
        private readonly JWTTokenManagerInterface $jwtTokenManager,
        private readonly MailerInterface $mailer,
        private readonly string $stripePublicKey,
        private readonly string $checkoutFromEmail,
    ) {
    }

    #[Route('/payment/checkout', name: 'payment_checkout', methods: ['GET'])]
    public function checkout(): Response
    {
        $publicKey = htmlspecialchars($this->stripePublicKey, ENT_QUOTES, 'UTF-8');

        $html = <<<HTML
<!DOCTYPE html>
<html lang="ca">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkout Stripe</title>
    <script src="https://js.stripe.com/v3/"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; max-width: 600px; }
        .panel { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
        input, button { width: 100%; padding: 0.7rem; margin-top: 0.5rem; }
        button { cursor: pointer; }
        #message { margin-top: 1rem; font-weight: 600; }
    </style>
</head>
<body>
    <h1>Pagament de 20€</h1>
    <p>Introdueix el teu JWT (amb claim <code>email</code>) per iniciar el pagament.</p>

    <div class="panel">
        <label for="jwt-token">JWT</label>
        <input id="jwt-token" type="text" placeholder="Bearer token">
        <button id="start-payment">Iniciar pagament</button>
    </div>

    <form id="payment-form" class="panel" style="display:none;">
        <div id="payment-element"></div>
        <button id="submit">Pagar 20€</button>
        <div id="message"></div>
    </form>

    <script>
        const stripe = Stripe('{$publicKey}');
        const paymentForm = document.getElementById('payment-form');
        const messageContainer = document.getElementById('message');
        let elements;

        async function createIntent() {
            const token = document.getElementById('jwt-token').value.trim();
            const response = await fetch('/payment/intent', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({})
            });

            const data = await response.json();
            if (!response.ok) {
                throw new Error(data.error || 'No s\\'ha pogut crear el pagament.');
            }
            return data.client_secret;
        }

        document.getElementById('start-payment').addEventListener('click', async () => {
            try {
                const clientSecret = await createIntent();
                elements = stripe.elements({ clientSecret });
                const paymentElement = elements.create('payment');
                paymentElement.mount('#payment-element');
                paymentForm.style.display = 'block';
                messageContainer.textContent = '';
            } catch (error) {
                messageContainer.textContent = error.message;
            }
        });

        paymentForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            if (!elements) {
                messageContainer.textContent = 'Primer has d\\'iniciar el pagament.';
                return;
            }

            const result = await stripe.confirmPayment({
                elements,
                confirmParams: {},
                redirect: 'if_required'
            });

            if (result.error) {
                messageContainer.textContent = result.error.message || 'Pagament fallit.';
                return;
            }

            messageContainer.textContent = 'Pagament completat correctament.';
        });
    </script>
</body>
</html>
HTML;

        return new Response($html);
    }

    #[Route('/payment/intent', name: 'payment_intent', methods: ['POST'])]
    public function createIntent(Request $request): JsonResponse
    {
        $customerEmail = $this->resolveCustomerEmailFromJwt($request);
        if ($customerEmail === null) {
            return new JsonResponse(['error' => 'Invalid or missing JWT email claim'], Response::HTTP_UNAUTHORIZED);
        }

        try {
            $paymentIntent = $this->stripeService->createPaymentIntent(
                amountInCents: self::FIXED_AMOUNT_CENTS,
                currency: 'eur',
                metadata: ['customer_email' => $customerEmail],
            );
        } catch (\RuntimeException|\UnexpectedValueException $exception) {
            return new JsonResponse(
                ['error' => $exception->getMessage()],
                Response::HTTP_BAD_GATEWAY
            );
        }

        if (!isset($paymentIntent['client_secret'], $paymentIntent['id'])) {
            return new JsonResponse(['error' => 'Stripe response missing fields'], Response::HTTP_BAD_GATEWAY);
        }

        return new JsonResponse([
            'client_secret' => $paymentIntent['client_secret'],
            'payment_intent_id' => $paymentIntent['id'],
            'amount' => self::FIXED_AMOUNT_EUR,
            'currency' => 'eur',
        ]);
    }

    #[Route('/payment/webhook', name: 'payment_webhook', methods: ['POST'])]
    public function webhook(Request $request): Response
    {
        $signatureHeader = $request->headers->get('Stripe-Signature');
        if (!is_string($signatureHeader)) {
            return new Response('Missing Stripe-Signature header', Response::HTTP_BAD_REQUEST);
        }

        try {
            $event = $this->stripeService->constructWebhookEvent($request->getContent(), $signatureHeader);
        } catch (\UnexpectedValueException $exception) {
            return new Response($exception->getMessage(), Response::HTTP_BAD_REQUEST);
        }

        $eventType = $event['type'] ?? null;
        if ($eventType === 'payment_intent.succeeded') {
            $paymentIntent = $event['data']['object'] ?? [];
            $customerEmail = $paymentIntent['metadata']['customer_email'] ?? null;

            if (!is_string($customerEmail) || trim($customerEmail) === '') {
                return new Response('Missing customer email metadata', Response::HTTP_BAD_REQUEST);
            }

            $email = (new Email())
                ->from($this->checkoutFromEmail)
                ->to($customerEmail)
                ->subject('Gràcies per la teva compra')
                ->text('Hem rebut correctament el teu pagament de 20€. Gràcies per confiar en nosaltres.');

            try {
                $this->mailer->send($email);
            } catch (TransportExceptionInterface $exception) {
                return new Response($exception->getMessage(), Response::HTTP_BAD_GATEWAY);
            }
        }

        return new Response('', Response::HTTP_OK);
    }

    private function resolveCustomerEmailFromJwt(Request $request): ?string
    {
        $authorizationHeader = $request->headers->get('Authorization');
        if (!is_string($authorizationHeader) || !str_starts_with($authorizationHeader, 'Bearer ')) {
            return null;
        }

        $token = trim(substr($authorizationHeader, 7));
        if ($token === '') {
            return null;
        }

        try {
            $payload = $this->jwtTokenManager->parse($token);
        } catch (JWTDecodeFailureException) {
            return null;
        }

        $email = $payload['email'] ?? null;
        if (!is_string($email) || trim($email) === '') {
            return null;
        }

        return $email;
    }
}
