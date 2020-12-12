// +build wireinject

package operation

import (
	"github.com/AlaskaAirlines/trivy/pkg/db"
	"github.com/google/wire"
)

func initializeDBClient(cacheDir string, quiet bool) db.Client {
	wire.Build(db.SuperSet)
	return db.Client{}
}
