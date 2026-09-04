CREATE TABLE `url_reputations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` int NOT NULL,
	`artifactId` int NOT NULL,
	`userId` int NOT NULL,
	`url` varchar(2048) NOT NULL,
	`provider` varchar(64) NOT NULL,
	`inDatabase` int NOT NULL DEFAULT 0,
	`phishId` int,
	`verified` int NOT NULL DEFAULT 0,
	`online` int NOT NULL DEFAULT 0,
	`target` varchar(512),
	`verifiedAt` timestamp,
	`feedUpdatedAt` timestamp,
	`rawJson` text,
	`enrichedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `url_reputations_id` PRIMARY KEY(`id`)
);
