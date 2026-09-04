CREATE TABLE `ip_geolocations` (
	`id` int AUTO_INCREMENT NOT NULL,
	`investigationId` int NOT NULL,
	`artifactId` int NOT NULL,
	`userId` int NOT NULL,
	`ip` varchar(64) NOT NULL,
	`country` varchar(128),
	`countryCode` varchar(8),
	`region` varchar(128),
	`city` varchar(128),
	`latitude` double,
	`longitude` double,
	`provider` varchar(128) NOT NULL,
	`enrichedAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `ip_geolocations_id` PRIMARY KEY(`id`)
);
