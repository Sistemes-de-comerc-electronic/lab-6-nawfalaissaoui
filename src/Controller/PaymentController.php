<?php

namespace App\Controller;

use App\Entity\Transaction;
use App\Repository\CarRepository;
use App\Repository\TransactionRepository;
use App\Service\StripeService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class PaymentController extends AbstractController
{
    public function __construct(
        private StripeService $stripeService,
        private CarRepository $carRepository,
        private TransactionRepository $transactionRepository
    ) {}

    #[Route('/payment/intent', name: 'payment_intent', methods: ['POST'])]
    public function createIntent(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        if (empty($data['car_id'])) {
            return new JsonResponse(['error' => 'car_id is required'], 400);
        }

        $car = $this->carRepository->find($data['car_id']);

        if (!$car) {
            return new JsonResponse(['error' => 'Car not found'], 404);
        }

        $paymentIntent = $this->stripeService->createPaymentIntent(
            amount: $car->getPrice(),
            currency: 'eur',
            metadata: [
                'car_id'   => $car->getId()->toRfc4122(),
                'car_name' => $car->getName(),
            ]
        );

        return new JsonResponse([
            'client_secret'     => $paymentIntent->client_secret,
            'payment_intent_id' => $paymentIntent->id,
            'amount'            => $car->getPrice(),
            'currency'          => 'eur',
        ], 200);
    }

    #[Route('/payment/webhook', name: 'payment_webhook', methods: ['POST'])]
    public function webhook(Request $request): Response
    {
        $payload   = $request->getContent();
        $sigHeader = $request->headers->get('Stripe-Signature');

        if (!$sigHeader) {
            return new Response('Missing Stripe-Signature header', 400);
        }

        try {
            $event = $this->stripeService->constructWebhookEvent($payload, $sigHeader);
        } catch (\Stripe\Exception\SignatureVerificationException $e) {
            return new Response('Invalid signature', 400);
        }

        switch ($event->type) {
            case 'payment_intent.succeeded':
                $paymentIntent = $event->data->object;

                $transaction = new Transaction();
                $transaction->setPaymentIntentId($paymentIntent->id);
                $transaction->setAmount($paymentIntent->amount / 100);
                $transaction->setCurrency($paymentIntent->currency);
                $transaction->setCarId($paymentIntent->metadata->car_id ?? '');

                $this->transactionRepository->save($transaction, true);
                break;

            case 'payment_intent.payment_failed':
                error_log('Pagament fallat: ' . $event->data->object->id);
                break;
        }

        return new Response('', 200);
    }

    #[Route('/transactions', name: 'get_transactions', methods: ['GET'])]
    public function getTransactions(): JsonResponse
    {
        $transactions = $this->transactionRepository->findAll();

        $data = array_map(fn($t) => [
            'id'               => $t->getId()->toRfc4122(),
            'paymentIntentId'  => $t->getPaymentIntentId(),
            'amount'           => $t->getAmount(),
            'currency'         => $t->getCurrency(),
            'carId'            => $t->getCarId(),
            'createdAt'        => $t->getCreatedAt()->format('Y-m-d H:i:s'),
        ], $transactions);

        return new JsonResponse($data, 200);
    }
}