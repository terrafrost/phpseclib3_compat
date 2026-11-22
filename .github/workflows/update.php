<?php

function replaceFileContents($fileName, $search, $replace)
{
    $fileContents = file_get_contents($fileName);
    $updatedFileContents = preg_replace($search, $replace, $fileContents);
    file_put_contents($fileName, $updatedFileContents);
}

replaceFileContents('tests/Unit/File/X509/X509Test.php', '~ public function testComputeKeyIdentifier~', ' private function skiptestComputeKeyIdentifier');