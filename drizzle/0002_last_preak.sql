ALTER TABLE `email_artifacts` ADD `aiCategory` varchar(80);--> statement-breakpoint
ALTER TABLE `email_artifacts` ADD `aiSummary` text;--> statement-breakpoint
ALTER TABLE `email_artifacts` ADD `aiSocialEngineering` text;--> statement-breakpoint
ALTER TABLE `email_artifacts` ADD `aiRecommendationsJson` text;--> statement-breakpoint
ALTER TABLE `email_artifacts` ADD `aiModel` varchar(128);