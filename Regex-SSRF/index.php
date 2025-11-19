<?php

require_once __DIR__ . '/vendor/autoload.php';

$mpdf = new \Mpdf\Mpdf(['tempDir' => __DIR__ . '/tmp']);

$sanitized_input = htmlentities($_POST['text'], ENT_QUOTES, encoding: 'UTF-8');
$html = "<html><head></head><body><b>" . $sanitized_input . "</b></body></html>";

$mpdf->WriteHTML($html);
$mpdf->Output('generated.pdf', 'I');