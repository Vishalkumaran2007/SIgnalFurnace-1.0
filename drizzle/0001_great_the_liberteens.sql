CREATE TABLE `email_artifacts` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` int NOT NULL,
	`userId` int NOT NULL,
	`originalFilename` varchar(512) NOT NULL,
	`storageKey` varchar(768) NOT NULL,
	`storageUrl` varchar(1024) NOT NULL,
	`mimeType` varchar(128) NOT NULL,
	`sha256` varchar(128) NOT NULL,
	`sender` varchar(512),
	`recipient` varchar(512),
	`subject` varchar(1024),
	`messageId` varchar(1024),
	`sentAt` timestamp,
	`bodyText` text,
	`rawHeaders` text,
	`spf` enum('pass','fail','neutral','missing') NOT NULL DEFAULT 'missing',
	`dkim` enum('pass','fail','neutral','missing') NOT NULL DEFAULT 'missing',
	`dmarc` enum('pass','fail','neutral','missing') NOT NULL DEFAULT 'missing',
	`replyTo` varchar(512),
	`returnPath` varchar(512),
	`originatingIp` varchar(64),
	`urlsJson` text,
	`attachmentNamesJson` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `email_artifacts_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `indicators` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` int NOT NULL,
	`userId` int NOT NULL,
	`type` enum('ip','domain','url','email','hash') NOT NULL,
	`value` varchar(2048) NOT NULL,
	`source` varchar(128) NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `indicators_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `investigation_events` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` int NOT NULL,
	`userId` int NOT NULL,
	`eventType` varchar(128) NOT NULL,
	`detail` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `investigation_events_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `investigation_notes` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` int NOT NULL,
	`userId` int NOT NULL,
	`content` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `investigation_notes_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `investigations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`caseNumber` varchar(48) NOT NULL,
	`title` varchar(512) NOT NULL,
	`status` enum('open','in_progress','resolved','closed') NOT NULL DEFAULT 'open',
	`severity` enum('safe','low','medium','high','critical') NOT NULL DEFAULT 'low',
	`threatScore` int NOT NULL DEFAULT 0,
	`confidence` int NOT NULL DEFAULT 0,
	`summary` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `investigations_id` PRIMARY KEY(`id`),
	CONSTRAINT `investigations_caseNumber_unique` UNIQUE(`caseNumber`)
);
