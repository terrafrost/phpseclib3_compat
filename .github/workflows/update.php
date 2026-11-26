<?php

function replaceFileContents($fileName, $search, $replace)
{
    $fileContents = file_get_contents($fileName);
    $updatedFileContents = preg_replace($search, $replace, $fileContents);
    file_put_contents($fileName, $updatedFileContents);
}

replaceFileContents('tests/Unit/File/X509/X509Test.php', '~ public function testComputeKeyIdentifier~', ' private function skiptestComputeKeyIdentifier');
// these use reflection to call ChaCha20's protected poly1305() / createPoly1305Key() methods
replaceFileContents('tests/Unit/Crypt/ChaCha20Test.php', '~ public function test252~', ' private function skiptest252');
replaceFileContents('tests/Unit/Crypt/ChaCha20Test.php', '~ public function test262~', ' private function skiptest262');