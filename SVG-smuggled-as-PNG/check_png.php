<?php
function isPNG($filePath) {
    return @exif_imagetype($filePath) === IMAGETYPE_PNG;
}

$fileToCheck = 'poc-svg.png';
echo isPNG($fileToCheck) ? 'exif_imagetype === IMAGETYPE_PNG' : 'Not a PNG';
echo "\n";
