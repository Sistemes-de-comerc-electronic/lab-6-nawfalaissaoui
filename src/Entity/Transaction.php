<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

#[ORM\Entity]
class Transaction
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    private Uuid $id;

    #[ORM\Column(type: 'string', length: 255)]
    private string $paymentIntentId;

    #[ORM\Column(type: 'decimal', precision: 10, scale: 2)]
    private float $amount;

    #[ORM\Column(type: 'string', length: 10)]
    private string $currency;

    #[ORM\Column(type: 'string', length: 255)]
    private string $carId;

    #[ORM\Column(type: 'datetime')]
    private \DateTime $createdAt;

    public function __construct(?Uuid $id = null)
    {
        $this->id = $id ?? Uuid::v4();
        $this->createdAt = new \DateTime();
    }

    public function getId(): Uuid { return $this->id; }
    public function getPaymentIntentId(): string { return $this->paymentIntentId; }
    public function setPaymentIntentId(string $paymentIntentId): void { $this->paymentIntentId = $paymentIntentId; }
    public function getAmount(): float { return $this->amount; }
    public function setAmount(float $amount): void { $this->amount = $amount; }
    public function getCurrency(): string { return $this->currency; }
    public function setCurrency(string $currency): void { $this->currency = $currency; }
    public function getCarId(): string { return $this->carId; }
    public function setCarId(string $carId): void { $this->carId = $carId; }
    public function getCreatedAt(): \DateTime { return $this->createdAt; }
}