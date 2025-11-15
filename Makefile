migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down

migrate-force:
	migrate -path migrations -database "$(DATABASE_URL)" force $(VERSION)