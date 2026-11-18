package policy

import "github.com/joshua-noel/chaperone/api"

// DefaultCatalog loads the catalog embedded from api/manual.yaml.
func DefaultCatalog() (*Catalog, error) {
	data, err := api.Files.ReadFile("manual.yaml")
	if err != nil {
		return nil, err
	}
	return LoadCatalog(data)
}

// Default returns the catalog and the baseline pack that ship with this build.
func Default() (*Catalog, *Pack, error) {
	cat, err := DefaultCatalog()
	if err != nil {
		return nil, nil, err
	}
	base, err := Baseline(cat)
	if err != nil {
		return nil, nil, err
	}
	return cat, base, nil
}
