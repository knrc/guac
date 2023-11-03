//
// Copyright 2023 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package inmem

import (
	"context"
	"reflect"
	"strconv"
	"time"

	"github.com/vektah/gqlparser/v2/gqlerror"

	"github.com/guacsec/guac/internal/testing/ptrfrom"
	"github.com/guacsec/guac/pkg/assembler/backends/inmem/helpers"
	"github.com/guacsec/guac/pkg/assembler/graphql/model"
)

// Internal data: link between packages and vulnerabilities (certifyVulnerability)
type certifyVulnerabilitySet struct{ helpers.SparseSet[uint32] }

type certifyVulnerabilityAttributeIndex uint32

const (
	certVuln_packageId = certifyVulnerabilityAttributeIndex(iota)
	certVuln_vulnerabilityID
	certVuln_timeScanned
	certVuln_dbURI
	certVuln_dbVersion
	certVuln_scannerURI
	certVuln_scannerVersion
	certVuln_origin
	certVuln_collector
)

var certVulnIDs = []certifyVulnerabilityAttributeIndex{
	certVuln_packageId,
	certVuln_vulnerabilityID,
	certVuln_timeScanned,
	certVuln_dbURI,
	certVuln_dbVersion,
	certVuln_scannerURI,
	certVuln_scannerVersion,
	certVuln_origin,
	certVuln_collector,
}

type certifyVulnerabilityLink struct {
	id              uint32
	packageID       uint32
	vulnerabilityID uint32
	timeScanned     time.Time
	dbURI           string
	dbVersion       string
	scannerURI      string
	scannerVersion  string
	origin          string
	collector       string
}

func (n *certifyVulnerabilityLink) ID() uint32 { return n.id }

func (n *certifyVulnerabilityLink) Neighbors(allowedEdges edgeMap) []uint32 {
	out := make([]uint32, 0, 2)
	if allowedEdges[model.EdgeCertifyVulnPackage] {
		out = append(out, n.packageID)
	}
	if n.vulnerabilityID != 0 && allowedEdges[model.EdgeCertifyVulnVulnerability] {
		out = append(out, n.vulnerabilityID)
	}
	return out
}

func (n *certifyVulnerabilityLink) BuildModelNode(c *demoClient) (model.Node, error) {
	return c.buildCertifyVulnerability(n, nil, true)
}

// Ingest CertifyVuln
func (c *demoClient) IngestCertifyVulns(ctx context.Context, pkgs []*model.PkgInputSpec, vulnerabilities []*model.VulnerabilityInputSpec, certifyVulns []*model.ScanMetadataInput) ([]*model.CertifyVuln, error) {
	var modelCertifyVulnList []*model.CertifyVuln
	for i := range certifyVulns {
		certifyVuln, err := c.IngestCertifyVuln(ctx, *pkgs[i], *vulnerabilities[i], *certifyVulns[i])
		if err != nil {
			return nil, gqlerror.Errorf("IngestCertifyVuln failed with err: %v", err)
		}
		modelCertifyVulnList = append(modelCertifyVulnList, certifyVuln)
	}
	return modelCertifyVulnList, nil
}

func (c *demoClient) IngestCertifyVuln(ctx context.Context, pkg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput) (*model.CertifyVuln, error) {
	return c.ingestVulnerability(ctx, pkg, vulnerability, certifyVuln, true)
}

func (c *demoClient) ingestVulnerability(ctx context.Context, packageArg model.PkgInputSpec, vulnerability model.VulnerabilityInputSpec, certifyVuln model.ScanMetadataInput, readOnly bool) (*model.CertifyVuln, error) {
	funcName := "IngestVulnerability"
	lock(&c.m, readOnly)
	defer unlock(&c.m, readOnly)

	packageID, err := getPackageIDFromInput(c, packageArg, model.MatchFlags{Pkg: model.PkgMatchTypeSpecificVersion})
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	foundPackage, err := byID[*pkgVersionNode](packageID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	// Create the sparse set here for now, ideally this would come from the discovered package/vulnerability
	var packageVulns certifyVulnerabilitySet
	packageVulns.InsertAll(foundPackage.certifyVulnLinks...)

	vulnID, err := getVulnerabilityIDFromInput(c, vulnerability)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	foundVulnNode, err := byID[*vulnIDNode](vulnID, c)
	if err != nil {
		return nil, gqlerror.Errorf("%v ::  %s", funcName, err)
	}
	// Create the sparse set here for now, ideally this would come from the discovered package/vulnerability
	var vulnerabilityLinks certifyVulnerabilitySet
	vulnerabilityLinks.InsertAll(foundVulnNode.certifyVulnLinks...)

	// Create the sparse set here for now, ideally this would come from the discovered package/vulnerability
	searchIDs := new(certifyVulnerabilitySet)
	searchIDs.Intersection(&packageVulns.SparseSet, &vulnerabilityLinks.SparseSet)

	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_packageId, packageID))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_vulnerabilityID, vulnID))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_timeScanned, certifyVuln.TimeScanned))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_dbURI, certifyVuln.DbURI))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_dbVersion, certifyVuln.DbVersion))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_scannerURI, certifyVuln.ScannerURI))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_scannerVersion, certifyVuln.ScannerVersion))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_origin, certifyVuln.Origin))
	searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_collector, certifyVuln.Collector))

	var collectedCertifyVulnLink *certifyVulnerabilityLink

	if !searchIDs.IsEmpty() {
		if err = searchIDs.ForEach(func(val uint32) error {
			collectedCertifyVulnLink, err = byID[*certifyVulnerabilityLink](val, c)
			return err
		}); err != nil {
			return nil, err
		}
	} else {
		if readOnly {
			c.m.RUnlock()
			cv, err := c.ingestVulnerability(ctx, packageArg, vulnerability, certifyVuln, false)
			c.m.RLock() // relock so that defer unlock does not panic
			return cv, err
		}
		// store the link
		collectedCertifyVulnLink = &certifyVulnerabilityLink{
			id:              c.getNextID(),
			packageID:       packageID,
			vulnerabilityID: vulnID,
			timeScanned:     certifyVuln.TimeScanned,
			dbURI:           certifyVuln.DbURI,
			dbVersion:       certifyVuln.DbVersion,
			scannerURI:      certifyVuln.ScannerURI,
			scannerVersion:  certifyVuln.ScannerVersion,
			origin:          certifyVuln.Origin,
			collector:       certifyVuln.Collector,
		}
		c.index[collectedCertifyVulnLink.id] = collectedCertifyVulnLink
		c.certifyVulnerabilities.Insert(collectedCertifyVulnLink.id)

		c.createCertifyVulnerabilityAttributeSet(certVuln_packageId, packageID).Insert(collectedCertifyVulnLink.id)

		c.createCertifyVulnerabilityAttributeSet(certVuln_vulnerabilityID, vulnID).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_timeScanned, certifyVuln.TimeScanned).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_dbURI, certifyVuln.DbURI).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_dbVersion, certifyVuln.DbVersion).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_scannerURI, certifyVuln.ScannerURI).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_scannerVersion, certifyVuln.ScannerVersion).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_origin, certifyVuln.Origin).Insert(collectedCertifyVulnLink.id)
		c.createCertifyVulnerabilityAttributeSet(certVuln_collector, certifyVuln.Collector).Insert(collectedCertifyVulnLink.id)

		// set the backlinks
		foundPackage.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		if vulnID != 0 {
			foundVulnNode.setVulnerabilityLinks(collectedCertifyVulnLink.id)
		}
	}

	// build return GraphQL type
	builtCertifyVuln, err := c.buildCertifyVulnerability(collectedCertifyVulnLink, nil, true)
	if err != nil {
		return nil, err
	}
	return builtCertifyVuln, nil
}

// Query CertifyVuln
func (c *demoClient) CertifyVuln(ctx context.Context, filter *model.CertifyVulnSpec) ([]*model.CertifyVuln, error) {
	c.m.RLock()
	defer c.m.RUnlock()
	funcName := "CertifyVuln"

	if filter != nil && filter.ID != nil {
		id64, err := strconv.ParseUint(*filter.ID, 10, 32)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: invalid ID %s", funcName, err)
		}
		id := uint32(id64)
		link, err := byID[*certifyVulnerabilityLink](id, c)
		if err != nil {
			// Not found
			return nil, nil
		}
		// If found by id, ignore rest of fields in spec and return as a match
		foundCertifyVuln, err := c.buildCertifyVulnerability(link, filter, true)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		return []*model.CertifyVuln{foundCertifyVuln}, nil
	}

	searchIDs := new(certifyVulnerabilitySet)
	if filter != nil && filter.Package != nil {
		pkgs, err := c.findPackageVersion(filter.Package)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		for _, pkg := range pkgs {
			searchIDs.InsertAll(pkg.certifyVulnLinks...)
		}
	}
	if searchIDs.IsEmpty() && filter != nil && filter.Vulnerability != nil &&
		filter.Vulnerability.NoVuln != nil && *filter.Vulnerability.NoVuln {

		exactVuln, err := c.exactVulnerability(&model.VulnerabilitySpec{
			Type:            ptrfrom.String(noVulnType),
			VulnerabilityID: ptrfrom.String(""),
		})
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			searchIDs.InsertAll(exactVuln.certifyVulnLinks...)
		}
	} else if searchIDs.IsEmpty() && filter != nil && filter.Vulnerability != nil {

		if filter.Vulnerability.NoVuln != nil && !*filter.Vulnerability.NoVuln {
			if filter.Vulnerability.Type != nil && *filter.Vulnerability.Type == noVulnType {
				return []*model.CertifyVuln{}, gqlerror.Errorf("novuln boolean set to false, cannot specify vulnerability type to be novuln")
			}
		}

		exactVuln, err := c.exactVulnerability(filter.Vulnerability)
		if err != nil {
			return nil, gqlerror.Errorf("%v :: %v", funcName, err)
		}
		if exactVuln != nil {
			searchIDs.InsertAll(exactVuln.certifyVulnLinks...)
		}
	}

	var out []*model.CertifyVuln
	if searchIDs.IsEmpty() {
		searchIDs.Copy(&c.certifyVulnerabilities.SparseSet)
	}

	if filter != nil {
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_timeScanned, filter.TimeScanned))
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_dbURI, filter.DbURI))
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_dbVersion, filter.DbVersion))
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_scannerURI, filter.ScannerURI))
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_scannerVersion, filter.ScannerVersion))
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_origin, filter.Origin))
		searchIDs.IntersectionWith(c.getCertifyVulnerabilityAttributeSet(certVuln_collector, filter.Collector))
	}

	searchIDs.ForEach(func(val uint32) error {
		link := c.index[val].(*certifyVulnerabilityLink)
		foundCertifyVuln, err := c.buildCertifyVulnerability(link, filter, false)
		if err != nil {
			return err
		}
		if foundCertifyVuln == nil || reflect.ValueOf(foundCertifyVuln.Vulnerability).IsNil() {
			return nil
		}
		out = append(out, foundCertifyVuln)
		return nil
	})
	return out, nil
}

func (c *demoClient) buildCertifyVulnerability(link *certifyVulnerabilityLink, filter *model.CertifyVulnSpec, ingestOrIDProvided bool) (*model.CertifyVuln, error) {
	var p *model.Package
	var vuln *model.Vulnerability
	var err error
	if filter != nil {
		p, err = c.buildPackageResponse(link.packageID, filter.Package)
		if err != nil {
			return nil, err
		}
	} else {
		p, err = c.buildPackageResponse(link.packageID, nil)
		if err != nil {
			return nil, err
		}
	}

	if filter != nil && filter.Vulnerability != nil {
		if filter.Vulnerability != nil && link.vulnerabilityID != 0 {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, filter.Vulnerability)
			if err != nil {
				return nil, err
			}
			if filter.Vulnerability.NoVuln != nil && !*filter.Vulnerability.NoVuln {
				if vuln != nil {
					if vuln.Type == noVulnType {
						vuln = nil
					}
				}
			}
		}
	} else {
		if link.vulnerabilityID != 0 {
			vuln, err = c.buildVulnResponse(link.vulnerabilityID, nil)
			if err != nil {
				return nil, err
			}
		}
	}

	// if package not found during ingestion or if ID is provided in filter, send error. On query do not send error to continue search
	if p == nil && ingestOrIDProvided {
		return nil, gqlerror.Errorf("failed to retrieve package via packageID")
	} else if p == nil && !ingestOrIDProvided {
		return nil, nil
	}

	if link.vulnerabilityID != 0 {
		if vuln == nil && ingestOrIDProvided {
			return nil, gqlerror.Errorf("failed to retrieve vuln via vulnID")
		} else if vuln == nil && !ingestOrIDProvided {
			return nil, nil
		}
	}

	metadata := &model.ScanMetadata{
		TimeScanned:    link.timeScanned,
		DbURI:          link.dbURI,
		DbVersion:      link.dbVersion,
		ScannerURI:     link.scannerURI,
		ScannerVersion: link.scannerVersion,
		Origin:         link.origin,
		Collector:      link.collector,
	}

	certifyVuln := model.CertifyVuln{
		ID:            nodeID(link.id),
		Package:       p,
		Vulnerability: vuln,
		Metadata:      metadata,
	}
	return &certifyVuln, nil
}

func newCertifyVulnerabilityAttributes() map[certifyVulnerabilityAttributeIndex]map[any]*certifyVulnerabilitySet {
	attrMap := make(map[certifyVulnerabilityAttributeIndex]map[any]*certifyVulnerabilitySet)
	for _, id := range certVulnIDs {
		attrMap[id] = make(map[any]*certifyVulnerabilitySet)
	}
	return attrMap
}

func (c *demoClient) createCertifyVulnerabilityAttributeSet(index certifyVulnerabilityAttributeIndex, id any) *certifyVulnerabilitySet {
	indexMap := c.certifyVulnerabilityAttributes[index]
	idSet := indexMap[id]
	if idSet == nil {
		idSet = new(certifyVulnerabilitySet)
		indexMap[id] = idSet
	}
	return idSet
}

func (c *demoClient) getCertifyVulnerabilityAttributeSet(index certifyVulnerabilityAttributeIndex, id any) *helpers.SparseSet[uint32] {
	idSet := c.certifyVulnerabilityAttributes[index][id]
	if idSet != nil {
		return &idSet.SparseSet
	}
	return nil
}
