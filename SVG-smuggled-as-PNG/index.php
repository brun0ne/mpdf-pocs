<?php

require_once __DIR__ . '/vendor/autoload.php';

$mpdf = new \Mpdf\Mpdf(['tempDir' => __DIR__ . '/tmp']);
$mpdf->WriteHTML($_POST['html']);
$mpdf->Output('generated.pdf', 'I');
