<?php
// Get the IP address from the URL parameter
$ip = $_GET['ip'];

// Execute the ping command
exec("ping -c 4 $ip", $output, $return_var);

// Display the result
echo "<pre>";
foreach ($output as $line) {
    echo htmlspecialchars($line) . "<br>";
}
echo "</pre>";

// Display the return status
echo "Return status: $return_var";
?>
