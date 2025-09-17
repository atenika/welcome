<?php
header("Content-Type: application/json");

// Odczytaj przesłane dane JSON
$dane = json_decode(file_get_contents("php://input"), true);

// Sprawdź czy wszystkie dane istnieją
if (!isset($dane['adresEthereum'], $dane['danetx1'], $dane['danetx2'])) {
    echo json_encode(['status' => 'error', 'message' => 'Brakujące dane']);
    exit;
}

// Utwórz linię danych do zapisu
$liniaDoZapisu = json_encode($dane) . PHP_EOL;

// Określ pełną ścieżkę do pliku na serwerze
$sciezka = '../private_data/broadcaster/przeslijdalej.json';

// Dodaj dane do pliku (append)
file_put_contents($sciezka, $liniaDoZapisu, FILE_APPEND);

// Zwróć sukces
echo json_encode(['status' => 'success']);

