package incidents

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

type fakeRepo struct {
	incidents map[string]domain.Incident
	gotLimit  int
}

func (f *fakeRepo) CreateIncident(_ context.Context, in *domain.Incident) error {
	in.ID = domain.NewID()
	in.Status = domain.IncidentOpen
	f.incidents[in.ID] = *in
	return nil
}

func (f *fakeRepo) GetIncident(_ context.Context, id string) (domain.Incident, error) {
	if inc, ok := f.incidents[id]; ok {
		return inc, nil
	}
	return domain.Incident{}, domain.ErrNotFound
}

func (f *fakeRepo) ListIncidents(_ context.Context, limit, _ int) ([]domain.Incident, error) {
	f.gotLimit = limit
	return nil, nil
}

func (f *fakeRepo) LatestReport(context.Context, string) (domain.InvestigationRecord, error) {
	return domain.InvestigationRecord{}, domain.ErrNotFound
}

func newService() (*Service, *fakeRepo) {
	repo := &fakeRepo{incidents: map[string]domain.Incident{}}
	return NewService(repo), repo
}

func TestCreateNormalizesAndStores(t *testing.T) {
	svc, repo := newService()
	inc, err := svc.Create(context.Background(), CreateInput{Title: "  Link down ", TargetHost: " GW.Example.NET ", TargetPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if inc.Title != "Link down" || inc.TargetHost != "gw.example.net" || repo.incidents[inc.ID].ID == "" {
		t.Fatalf("unexpected incident: %+v", inc)
	}
}

func TestCreateValidation(t *testing.T) {
	tests := []struct {
		name  string
		in    CreateInput
		field string
	}{
		{"missing title", CreateInput{TargetHost: "a.com"}, "title"},
		{"long title", CreateInput{Title: strings.Repeat("x", 201), TargetHost: "a.com"}, "title"},
		{"long description", CreateInput{Title: "t", Description: strings.Repeat("x", 5001), TargetHost: "a.com"}, "description"},
		{"missing host", CreateInput{Title: "t"}, "target_host"},
		{"injection host", CreateInput{Title: "t", TargetHost: "a.com; reboot"}, "target_host"},
		{"bad port", CreateInput{Title: "t", TargetHost: "a.com", TargetPort: 70000}, "target_port"},
	}
	svc, _ := newService()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.Create(context.Background(), tt.in)
			var ve *ValidationError
			if !errors.As(err, &ve) || ve.Field != tt.field {
				t.Fatalf("want validation error on %s, got %v", tt.field, err)
			}
		})
	}
}

func TestListClampsLimit(t *testing.T) {
	svc, repo := newService()
	for _, tc := range []struct{ in, want int }{{0, DefaultPageSize}, {-5, DefaultPageSize}, {50, 50}, {1000, MaxPageSize}} {
		if _, err := svc.List(context.Background(), tc.in, 0); err != nil {
			t.Fatal(err)
		}
		if repo.gotLimit != tc.want {
			t.Errorf("limit %d -> %d, want %d", tc.in, repo.gotLimit, tc.want)
		}
	}
	if _, err := svc.List(context.Background(), 10, -1); err == nil {
		t.Fatal("negative offset accepted")
	}
}

func TestReportNotFound(t *testing.T) {
	svc, _ := newService()
	_, err := svc.Report(context.Background(), domain.NewID())
	if !errors.Is(err, domain.ErrNotFound) || !strings.Contains(err.Error(), "incident") {
		t.Fatalf("got %v", err)
	}
	inc, _ := svc.Create(context.Background(), CreateInput{Title: "t", TargetHost: "a.com"})
	_, err = svc.Report(context.Background(), inc.ID)
	if !errors.Is(err, domain.ErrNotFound) || !strings.Contains(err.Error(), "completed investigation") {
		t.Fatalf("got %v", err)
	}
}
