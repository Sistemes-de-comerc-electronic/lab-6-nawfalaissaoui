<?php

namespace App\Controller;

use App\Repository\CarRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class CarController extends AbstractController
{
    public function __construct(
        private CarRepository $carRepository
    ) {}

    #[Route('/cars/{id}', name: 'get_car', methods: ['GET'])]
    public function getCar(string $id): JsonResponse
    {
        try {
            $uuid = \Symfony\Component\Uid\Uuid::fromString($id);
        } catch (\Exception $e) {
            return new JsonResponse(['error' => 'Invalid UUID'], 400);
        }

        $car = $this->carRepository->find($uuid);

        if (!$car) {
            return new JsonResponse(['error' => 'Car not found'], 404);
        }

        return new JsonResponse([
            'id'    => $car->getId()->toRfc4122(),
            'name'  => $car->getName(),
            'model' => $car->getModel(),
            'year'  => $car->getYear(),
            'price' => $car->getPrice(),
            'brand' => [
                'id'   => $car->getBrand()->getId()->toRfc4122(),
                'name' => $car->getBrand()->getName(),
            ],
        ], 200);
    }

    #[Route('/cars/{id}', name: 'delete_car', methods: ['DELETE'])]
    public function deleteCar(string $id): JsonResponse
    {
        try {
            $uuid = \Symfony\Component\Uid\Uuid::fromString($id);
        } catch (\Exception $e) {
            return new JsonResponse(['error' => 'Invalid UUID'], 400);
        }

        $car = $this->carRepository->find($uuid);

        if (!$car) {
            return new JsonResponse(['error' => 'Car not found'], 404);
        }

        $this->carRepository->getEntityManager()->remove($car);
        $this->carRepository->getEntityManager()->flush();

        return new JsonResponse(null, 204);
    }

    #[Route('/cars', name: 'create_car', methods: ['POST'])]
    public function createCar(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);

        if (empty($data['name']) || empty($data['model']) || empty($data['year']) || empty($data['price']) || empty($data['brand_id'])) {
            return new JsonResponse(['error' => 'Missing required fields'], 400);
        }

        $brand = $this->carRepository->getEntityManager()->getRepository(\App\Entity\Brand::class)->find($data['brand_id']);

        if (!$brand) {
            return new JsonResponse(['error' => 'Brand not found'], 404);
        }

        $car = new \App\Entity\Car();
        $car->setName($data['name']);
        $car->setModel($data['model']);
        $car->setYear((int) $data['year']);
        $car->setPrice((float) $data['price']);
        $car->setBrand($brand);

        $this->carRepository->save($car, true);

        return new JsonResponse(['id' => $car->getId()->toRfc4122()], 201);
    }
}