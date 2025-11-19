<?php

class VulnerableClass {
    public $data;

    public function __destruct() {
        /* This obviously would not be in a real application,
           it's just to demonstrate that executing __destruct
           through phar deserialization is possible. 
           
           Real exploits would need to build a gadget chain. */

        file_put_contents('/var/www/html/pwned', $this->data);
    }
}

require_once __DIR__ . '/vendor/autoload.php';

$mpdf = new \Mpdf\Mpdf(['tempDir' => __DIR__ . '/tmp']);
$mpdf->WriteHTML("<img src='/tmp/poc.svg' />");
$mpdf->Output('generated.pdf', 'I');
