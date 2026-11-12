-- Adds a dedicated primary resale category to creator applications.
ALTER TABLE partner_applications ADD COLUMN resale_category TEXT;
