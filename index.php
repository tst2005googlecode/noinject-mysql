<?php
$db = "percona";
$table = "whitelist";
$table_exception = "whitelist_exception";

$user="noinject";
$pass="injectno";
$host="127.0.0.1";

// DO NOT MODIFY BELOW HERE
$fqtn = $db . "." . $table;
$fqten = $db . "." . $table_exception;
$conn = mysqli_connect($host, $user, $pass);

if(!$conn) {
	throw new Exception('Could not connect to database');
}

$whitelist_sql = "select *, conv(checksum, 10, 16) hex_checksum from $fqtn where 1=1";
$count_sql = "select count(*) from $fqtn where 1=1";

$checksum="";
$sample="";

/* default order by */
$order_by = "last_seen";
$dir = "desc";

$page = 1;
$page_by = 20;
if(!empty($_REQUEST)) {

	if(!empty($_REQUEST['deny'])) {
		foreach($_REQUEST['deny'] as $k => $v) {
			if(!is_numeric($v)) unset($_REQUEST['deny'][$k]);
		}
		$sql = "UPDATE $fqtn SET reviewed_on = now(), comments=CONCAT('Set to deny: ', now()), reviewed_by = 'deny' WHERE reviewed_by != 'deny' and checksum IN (" . join(",", $_REQUEST['deny']) . ")";
		$stmt = mysqli_query($conn, $sql);
		if(!$stmt) throw new Exception("Could not update!");
	}
	if(!empty($_REQUEST['allow'])) {
		foreach($_REQUEST['allow'] as $k => $v) {
			if(!is_numeric($v)) unset($_REQUEST['allow'][$k]);
		}
		$sql = "UPDATE $fqtn SET reviewed_on = now(), comments=CONCAT('Set to allow: ', now()), reviewed_by = 'allow' WHERE reviewed_by != 'allow' and checksum IN (" . join(",", $_REQUEST['allow']) . ")";
		$stmt = mysqli_query($conn, $sql);
		if(!$stmt) throw new Exception("Could not update!");
	}

	/* escape the string fields properly */
	if(!empty($_REQUEST['checksum'])) {
		$whitelist_sql .= " AND checksum like '%" . mysqli_real_escape_string($conn, $_REQUEST['checksum']) . "%'";
		$count_sql .= " AND checksum like '%" . mysqli_real_escape_string($conn, $_REQUEST['checksum']) . "%'";
		$checksum = $_REQUEST['checksum'];	
	}
	if(!empty($_REQUEST['sample'])) { 
		$whitelist_sql .= " AND sample like '%" . mysqli_real_escape_string($conn, $_REQUEST['sample']) . "%'";
		$count_sql .= " AND sample like '%" . mysqli_real_escape_string($conn, $_REQUEST['sample']) . "%'";
		$sample = $_REQUEST['sample'];
	}

	/*whitelist the order by*/
	if(!empty($_REQUEST['order_by'])) {
		switch($_REQUEST['order_by']) {
			case 'last_seen':
			case 'first_seen':
			case 'reviewed_on':
			case 'checksum':
				$order_by = $_REQUEST['order_by'];
		}
	}

	/* whitelist the order by */
	if(!empty($_REQUEST['dir'])) {
		if(strtolower($_REQUEST['dir'][0]) == 'a') {
			$dir = 'asc';
		}
	}

	/* Check numeric data types before interpolation */
	if(!empty($_REQUEST['page_by'])) {
		if(is_numeric($_REQUEST['page_by'])) {
			$page_by = $_REQUEST['page_by'];
		}
	}

	if(!empty($_REQUEST['page'])) {
		if(is_numeric($_REQUEST['page'])) {
			$page = $_REQUEST['page'];
		}
	}

}

$whitelist_sql .= " order by $order_by $dir";

$offset = ($page - 1) * $page_by;
$whitelist_sql .= " LIMIT $offset, $page_by";

$stmt = mysqli_query($conn, $whitelist_sql);
if(!$stmt) throw new Exception('Could not get list of queries from database');
while($row = mysqli_fetch_assoc($stmt)) {
	$rows[] = $row;
}
$stmt = mysqli_query($conn, $count_sql);
$count = mysqli_fetch_array($stmt);
$count = $count[0];
if($page_by >= 0) {
	$pages = $count / $page_by;
	unset($_REQUEST['page_by']);
	for($i=0;$i<$pages;++$i) {
		$linklist = "<a href='" . make_request(array('page' => ( $i + 1 ) )) . "'>" . ($i + 1) . "</a> "; 	
	}
}

function make_request($add) {
	$r = "";
	foreach($_REQUEST as $k => $v) {
		if($r) $r .= '&';
		$r .= urlencode($k) . "=" . urlencode($v);	
	}
	foreach($add as $k => $v) {
		if($r) $r .= '&';
		$r .= urlencode($k) . "=" . urlencode($v);	
	}
	return "?$r";
}
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
   "http://www.w3.org/TR/html4/strict.dtd">
<HTML>
<head>
<title>NOINJECT! - Whitelist Interface 1.0</title>
<script>
function clickCheck(mode, checksum) {
	if(mode == "deny") {
		var el = document.getElementById("deny_" + checksum);
		var el2 = document.getElementById("allow_" + checksum);
	} else {
		var el = document.getElementById("allow_" + checksum);
		var el2 = document.getElementById("deny_" + checksum);
	} 
	el2.checked = !el.checked;
}
</script>
</head>
<body>
<table border=0 width="100%"><tr><td width=33% valign='bottom'>
<font color="#005500" size=+5 face="Times New Roman">NOINJECT!</font><br>
<a href="exceptions.php">See security exceptions</a>
</td><td valign='top'>
<img src="small.jpg" height=200 align=right>
</td></tr></table>
<form method="post" action="index.php" id='frm'>
<p>
<h4>Search<hr></h4>checksum: <input type="text" name="checksum" value="<?php echo $checksum;?>">&nbsp; sample: <input type="text" name="sample" value="<?php echo $sample;?>"><br>
Order by:<select name="order_by">
<option value="first_seen" <?php if($order_by == "first_seen") echo "selected";?>>First Seen</option>
<option value="last_seen" <?php if($order_by == "last_seen") echo "selected";?>>Last Seen</option>
<option value="reviewed_on" <?php if($order_by == "reviewed_on") echo "selected";?>>Last Updated</option>
</select>
Direction: <select name="dir">
<option value="a" <?php if ($dir=='asc') echo 'selected';?>>Asc</option>
<option value="d" <?php if ($dir=="desc") echo "selected"; ?>>Desc</option>
</select><p><input type="submit" value="Search"><br>
<h3>Whitelist
<hr>
</h3>
</form>
<form method="post" action="index.php" id='frm'>
<input type="submit" value="Update whitelist">
<?php
echo("<br>Page: " . $linklist . "<br>");
?>
<p>
<table border=3 width="100%" cellspacing=15 cellpadding=10>
<tr><th>Deny<th>Allow<th>Info<th>Sample</tr>
<?php
foreach($rows as $row) {
	echo "<tr>";
	echo "<td valign='center' align='center'>";
	echo "<img src='deny.png' height='60px' onclick=\"el = document.getElementById('deny_' + '{$row['checksum']}'); el.checked=true;clickCheck('deny','{$row['checksum']}');\">";
	$checked = "";
	if($row['reviewed_by'] !== 'allow') $checked = "checked";
	echo "<input name='deny[]' onchange=\"clickCheck('deny','{$row['checksum']}')\" id='deny_{$row['checksum']}' type='checkbox' value='{$row['checksum']}' $checked>";
	echo "</div>";
	echo "<td valign='center' align='center'><img onclick=\"el = document.getElementById('allow_' + '{$row['checksum']}'); el.checked=true;clickCheck('allow','{$row['checksum']}');\" height='60px' src='allow.png'>";
	$checked = "";
	if($row['reviewed_by'] === 'allow') $checked = "checked";
	echo "<input name='allow[]' onchange=\"clickCheck('allow','{$row['checksum']}')\" id='allow_{$row['checksum']}' type='checkbox' value='{$row['checksum']}' $checked>";
	echo "</td><td valign='center'>";
	echo "Checksum:&nbsp;" . $row['hex_checksum']  . "<br>";
	echo "First_seen:&nbsp;" . $row['first_seen']  . "<br>";
	echo "Last_seen:&nbsp;" . $row['last_seen']  . "<br>";
	echo "Note:&nbsp;<font color=red>" . $row['comments'] . "</font>";
	echo "</td>";
	echo "<td valign='top'><table cellpadding=0><tr><td><textarea cols=80 rows=6>{$row['sample']}</textarea></td></tr></table></td>";
	echo "</tr>";
}
?>
</table>
<p>
<input type="submit" value="Update whitelist">
<?php
echo("<br>Page: " . $linklist . "<br>");
?>
</form>
</body>
</html>
