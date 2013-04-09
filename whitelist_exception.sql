CREATE TABLE `whitelist_exception` (
  `checksum` bigint(20) unsigned DEFAULT NULL,
  `query_text` text,
  `exception_when` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',
  `seq` bigint(20) NOT NULL AUTO_INCREMENT,
  `action` enum('allowed','denied') DEFAULT NULL,
  `exception_ip` varchar(32) DEFAULT NULL,
  `exception_user` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`exception_when`,`seq`),
  UNIQUE KEY `seq` (`seq`)
) ENGINE=InnoDB AUTO_INCREMENT=61 DEFAULT CHARSET=utf8;
