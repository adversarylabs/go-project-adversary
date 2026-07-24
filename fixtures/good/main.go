package good

type Policy struct{ Enabled bool }

func (p Policy) Allows() bool { return p.Enabled }
