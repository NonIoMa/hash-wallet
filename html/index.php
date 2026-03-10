<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>

<body>
    <?php
    echo "<h1>TEST</h1>";
    echo "Wallet generator<br>";

    $output = shell_exec("PYTHONPATH=/var/www/assets python3 /var/www/python/makewallet.py 2>&1");

    echo "<pre>$output</pre>";
    ?>
</body>

</html>