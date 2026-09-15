CREATE TABLE `security_audit_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`actorRole` enum('user','admin') NOT NULL,
	`eventType` varchar(128) NOT NULL,
	`resourceType` varchar(128),
	`resourceId` varchar(128),
	`metadataJson` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `security_audit_events_id` PRIMARY KEY(`id`)
);
