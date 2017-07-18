package cvescan

type RuleResources []*Resource

func (r RuleResources) Valid() error {
	for idx := 0; idx < len(r); idx++ {
		_, err := r[idx].FetchUpdateResource()
		if err != nil {
			return err
		}
	}
	return nil
}
