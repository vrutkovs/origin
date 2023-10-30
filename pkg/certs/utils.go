//go:generate rm -rf ./raw-data .
//go:generate cp -r ../../tls/raw-data .
package certs

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"

	"github.com/openshift/library-go/pkg/certs/cert-inspection/certgraphapi"
	"k8s.io/apimachinery/pkg/util/sets"
)

//go:embed raw-data/*.json
var pkiInfoDir embed.FS

const rawTLSRootDir = "raw-data"

func GetPKIInfoFromRawData(rawTLSInfoDir string) (*certgraphapi.PKIRegistryInfo, error) {
	certs := SecretInfoByNamespaceName{}
	caBundles := ConfigMapInfoByNamespaceName{}

	err := filepath.WalkDir(rawTLSInfoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		filename := filepath.Join(rawTLSInfoDir, d.Name())
		currBytes, err := os.ReadFile(filename)
		if err != nil {
			return err
		}
		parsePKIInfo(currBytes, certs, caBundles)
		return nil
	})
	if err != nil {
		return nil, err
	}

	return certsToRegistryInfo(certs, caBundles), nil
}

func GetPKIInfoFromEmbeddedRawData() (*certgraphapi.PKIRegistryInfo, error) {
	certs := SecretInfoByNamespaceName{}
	caBundles := ConfigMapInfoByNamespaceName{}

	dir, err := pkiInfoDir.ReadDir(rawTLSRootDir)
	if err != nil {
		return nil, err
	}
	for _, file := range dir {
		if file.IsDir() {
			continue
		}
		currBytes, err := pkiInfoDir.ReadFile(filepath.Join(rawTLSRootDir, file.Name()))
		if err != nil {
			continue
		}
		parsePKIInfo(currBytes, certs, caBundles)
	}

	return certsToRegistryInfo(certs, caBundles), nil
}

func parsePKIInfo(currBytes []byte, certs SecretInfoByNamespaceName, caBundles ConfigMapInfoByNamespaceName) error {
	currPKI := &certgraphapi.PKIList{}
	err := json.Unmarshal(currBytes, currPKI)
	if err != nil {
		return err
	}

	for i := range currPKI.InClusterResourceData.CertKeyPairs {
		currCert := currPKI.InClusterResourceData.CertKeyPairs[i]
		existing, ok := certs[currCert.SecretLocation]
		if ok && !reflect.DeepEqual(existing, currCert.CertKeyInfo) {
			return fmt.Errorf("mismatch of certificate info")
		}

		certs[currCert.SecretLocation] = currCert.CertKeyInfo
	}
	for i := range currPKI.InClusterResourceData.CertificateAuthorityBundles {
		currCert := currPKI.InClusterResourceData.CertificateAuthorityBundles[i]
		existing, ok := caBundles[currCert.ConfigMapLocation]
		if ok && !reflect.DeepEqual(existing, currCert.CABundleInfo) {
			return fmt.Errorf("mismatch of certificate info")
		}

		caBundles[currCert.ConfigMapLocation] = currCert.CABundleInfo
	}
	return nil
}

func certsToRegistryInfo(certs SecretInfoByNamespaceName, caBundles ConfigMapInfoByNamespaceName) *certgraphapi.PKIRegistryInfo {
	result := &certgraphapi.PKIRegistryInfo{}

	certKeys := sets.KeySet[certgraphapi.InClusterSecretLocation, certgraphapi.PKIRegistryCertKeyPairInfo](certs).UnsortedList()
	sort.Sort(SecretRefByNamespaceName(certKeys))
	for _, key := range certKeys {
		result.CertKeyPairs = append(result.CertKeyPairs, certgraphapi.PKIRegistryInClusterCertKeyPair{
			SecretLocation: key,
			CertKeyInfo:    certs[key],
		})
	}

	caKeys := sets.KeySet[certgraphapi.InClusterConfigMapLocation, certgraphapi.PKIRegistryCertificateAuthorityInfo](caBundles).UnsortedList()
	sort.Sort(ConfigMapRefByNamespaceName(caKeys))
	for _, key := range caKeys {
		result.CertificateAuthorityBundles = append(result.CertificateAuthorityBundles, certgraphapi.PKIRegistryInClusterCABundle{
			ConfigMapLocation: key,
			CABundleInfo:      caBundles[key],
		})
	}
	return result
}
