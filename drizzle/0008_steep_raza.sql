CREATE TABLE `campaigns` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`name` varchar(255) NOT NULL,
	`iocType` enum('ip','domain','url','email','hash') NOT NULL,
	`iocValue` varchar(2048) NOT NULL,
	`caseIds` json NOT NULL,
	`caseCount` int NOT NULL DEFAULT 0,
	`firstSeen` timestamp NOT NULL DEFAULT (now()),
	`lastSeen` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `campaigns_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `evidence_chain` (
	`id` int AUTO_INCREMENT NOT NULL,
	`caseId` int NOT NULL,
	`blockNumber` int NOT NULL,
	`evidenceHash` varchar(64) NOT NULL,
	`previousHash` varchar(64) NOT NULL,
	`merkleRoot` varchar(64) NOT NULL,
	`analystId` int NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `evidence_chain_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `iocs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`caseId` int NOT NULL,
	`userId` int NOT NULL,
	`type` enum('ip','domain','url','email','hash') NOT NULL,
	`value` varchar(2048) NOT NULL,
	`firstSeen` timestamp NOT NULL DEFAULT (now()),
	`lastSeen` timestamp NOT NULL DEFAULT (now()),
	`occurrenceCount` int NOT NULL DEFAULT 1,
	CONSTRAINT `iocs_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `ip_geo_cache` (
	`ip` varchar(64) NOT NULL,
	`resultJson` json NOT NULL,
	`fetchedAt` timestamp NOT NULL DEFAULT (now()),
	`expiresAt` timestamp NOT NULL,
	CONSTRAINT `ip_geo_cache_ip` PRIMARY KEY(`ip`)
);
--> statement-breakpoint
ALTER TABLE `email_artifacts` ADD `attachmentAnalysisJson` text;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `postal` varchar(32);--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `timezone` varchar(128);--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `asn` varchar(64);--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `ispName` varchar(512);--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `organization` varchar(512);--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `isVpn` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `isTor` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `isHosting` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `isMobile` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `isSuspicious` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `infrastructureLabel` varchar(64);--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `abuseScore` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `abuseReports` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `lastReportedAt` timestamp;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `precisionConfidence` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `sourcesUsedJson` text;--> statement-breakpoint
ALTER TABLE `ip_geolocations` ADD `sourcesAgreed` int DEFAULT 0 NOT NULL;