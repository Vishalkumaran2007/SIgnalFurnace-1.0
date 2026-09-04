ALTER TABLE `ip_reputations` ADD `malicious` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `suspicious` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `harmless` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `undetected` int DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `reputationScore` int;--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `asn` int;--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `asOwner` varchar(512);--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `network` varchar(128);--> statement-breakpoint
ALTER TABLE `ip_reputations` ADD `lastAnalysisAt` timestamp;