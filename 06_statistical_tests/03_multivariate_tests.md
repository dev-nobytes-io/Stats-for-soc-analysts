# Multivariate Statistical Tests for Threat Hunting

Multivariate methods analyze multiple variables simultaneously, capturing complex interaction patterns that univariate or bivariate tests miss. In threat hunting, these methods identify clusters of similar behavior, reduce high-dimensional telemetry into interpretable components, and isolate anomalous entities based on their position in multi-feature space.

---

## 1. Principal Component Analysis (PCA)

### What It Analyzes
Dimensionality reduction technique that transforms correlated features into uncorrelated principal components ranked by explained variance. Anomalies appear as points distant from the primary component structure.

### Formula
```
Covariance matrix: C = (1/n) × XᵀX  (after centering)

Eigendecomposition: C = VΛVᵀ

Principal components: Z = XV

Reconstruction error (anomaly score):
E = ||x - x̂||²  where x̂ = reconstruction using top-k components
```

### Outputs
- Principal components (eigenvectors)
- Explained variance ratio per component
- Component scores per observation
- Reconstruction error per observation (anomaly score)
- Biplot for visualization

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | n × p matrix | n observations, p features (all numeric) |
| k | Integer | Number of components to retain |
| Output | n × k matrix | Transformed component scores |
| Anomaly Score | Float | Reconstruction error per observation |

### Assumptions
- Continuous numeric features
- Features should be standardized (mean=0, std=1) before PCA
- Linear relationships between features assumed
- Large enough sample (n >> p recommended)

### Limitations
- Only captures linear structure — misses nonlinear patterns
- Sensitive to outliers (consider robust PCA for security data)
- Interpretation of components requires domain expertise
- Computationally expensive for very high-dimensional data

### Cybersecurity Use Case
**Network Traffic Behavioral Fingerprinting**

With features [bytes_in, bytes_out, packet_count, unique_ports, session_count, duration], PCA reduces to 2-3 components explaining 90%+ of variance. Hosts with high reconstruction error are behaviorally atypical — candidates for investigation. Threat actors using living-off-the-land techniques often appear as low reconstruction error entities (they blend in) while noisy attackers appear as high-error outliers.

Also used for:
- User behavior analytics (UEBA) — identifying deviating user sessions
- Reducing log feature space for ML pipeline input
- Comparing pre/post-incident behavioral shift

### Splunk SPL Example (Feature Preparation)
```spl
index=network
| bucket _time span=1d
| stats
    sum(bytes_in) as bytes_in,
    sum(bytes_out) as bytes_out,
    dc(dest_port) as unique_ports,
    count as conn_count,
    avg(duration) as avg_duration
  by _time, src_ip
| eventstats
    avg(bytes_in) as mu_bi, stdev(bytes_in) as std_bi,
    avg(bytes_out) as mu_bo, stdev(bytes_out) as std_bo,
    avg(unique_ports) as mu_up, stdev(unique_ports) as std_up,
    avg(conn_count) as mu_cc, stdev(conn_count) as std_cc
| eval z_bytes_in = (bytes_in - mu_bi) / std_bi
| eval z_bytes_out = (bytes_out - mu_bo) / std_bo
| eval z_ports = (unique_ports - mu_up) / std_up
| eval z_conns = (conn_count - mu_cc) / std_cc
| table _time, src_ip, z_bytes_in, z_bytes_out, z_ports, z_conns
```
*Note: Full PCA computation requires MLTK or external Python. SPL above prepares standardized feature matrix.*

---

## 2. K-Means Clustering

### What It Analyzes
Partitions observations into k clusters by minimizing within-cluster sum of squared distances to cluster centroids. Entities in small/sparse clusters or far from any centroid are anomalous.

### Formula
```
Objective: minimize Σk Σi∈Ck ||xi - μk||²

Assignment step: Ck = {xi : ||xi - μk||² ≤ ||xi - μj||² ∀j}
Update step: μk = (1/|Ck|) Σi∈Ck xi

Anomaly score: distance_to_centroid = ||xi - μk(xi)||
```

### Outputs
- Cluster assignment per observation
- Cluster centroids
- Within-cluster sum of squares (WCSS)
- Distance to centroid per observation
- Silhouette score (cluster quality)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | n × p numeric matrix | Standardized features |
| k | Integer | Number of clusters (use elbow method) |
| Output | Integer per record | Cluster label |
| Anomaly Score | Float | Distance to assigned centroid |

### Assumptions
- Clusters are roughly spherical and similar size
- Features are numeric and standardized
- k must be specified in advance
- Sensitive to initialization (use k-means++ initialization)

### Limitations
- Must choose k — wrong k yields meaningless clusters
- Fails with non-spherical cluster shapes
- Sensitive to outliers (outliers distort centroid locations)
- Not deterministic — results vary across runs without fixed seed
- No native handling of categorical features

### Cybersecurity Use Case
**Peer Group Behavior Analysis for Insider Threat**

Cluster users by behavioral features (login_hour_variance, unique_systems_accessed, off_hours_activity_ratio, data_volume_z). Users in the large "normal" cluster are peers. Users isolated in small clusters or with large centroid distances are behavioral outliers requiring review — classic insider threat or compromised account signal.

Also used for:
- Grouping hosts by network behavior (identify rogue hosts)
- Segmenting malware families by behavioral features
- Alert triage — grouping similar alerts for bulk review

### Splunk SPL Example (MLTK)
```spl
index=endpoint
| bucket _time span=1d
| stats
    dc(dest_ip) as unique_dests,
    dc(process_name) as unique_processes,
    sum(bytes_out) as bytes_out,
    count as event_count
  by _time, src_ip
| fit StandardScaler unique_dests unique_processes bytes_out event_count
| fit KMeans k=5 unique_dests_scaled unique_processes_scaled bytes_out_scaled event_count_scaled
    into hunt_kmeans_model
| eval anomaly = if(cluster_distance > 2.5, "OUTLIER", "normal")
| where anomaly = "OUTLIER"
```

---

## 3. Hierarchical Clustering

### What It Analyzes
Builds a tree (dendrogram) of clusters by iteratively merging (agglomerative) or splitting (divisive) groups based on similarity. Allows variable granularity without pre-specifying k.

### Formula
```
Agglomerative: start with n singletons, merge closest pair iteratively

Linkage methods:
  Single:   d(A,B) = min(d(a,b)) ∀a∈A, b∈B
  Complete: d(A,B) = max(d(a,b)) ∀a∈A, b∈B
  Average:  d(A,B) = avg(d(a,b)) ∀a∈A, b∈B
  Ward:     minimizes within-cluster variance (preferred for security)

Cut dendrogram at height h to get clusters
```

### Outputs
- Dendrogram (tree structure)
- Cluster assignment at chosen height
- Cophenetic correlation coefficient (quality measure)
- Pairwise distance matrix

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | n × p feature matrix | Security metrics per entity |
| Linkage | Enum | Ward (default), complete, average |
| Cut Height | Float | Controls number of resulting clusters |
| Output | Integer per record | Cluster label |

### Assumptions
- Can handle non-spherical clusters (better than K-Means)
- Ward linkage assumes approximately equal cluster sizes
- Complete linkage handles outliers better than single linkage

### Limitations
- O(n² log n) time — not suitable for large datasets (> 10k entities)
- Cut height selection is subjective
- Does not update when new data arrives (static structure)

### Cybersecurity Use Case
**Malware Family Behavioral Taxonomy**

After sandbox analysis of 200 malware samples, hierarchical clustering on behavioral features (API calls, registry keys touched, network patterns) builds a dendrogram revealing family relationships. Samples merging at high heights are behaviorally distinct — potentially novel families or variants.

### Splunk SPL Example (Feature Prep)
```spl
index=sandbox
| stats
    dc(api_call) as unique_api,
    dc(registry_key) as unique_reg,
    dc(network_dest) as unique_net,
    sum(file_ops) as file_ops
  by sample_hash
| eval feature_vec = unique_api . "," . unique_reg . "," . unique_net . "," . file_ops
| outputlookup sandbox_features.csv
```
*Dendrogram computation requires Python/MLTK; SPL above exports feature matrix.*

---

## 4. Isolation Forest

### What It Analyzes
Anomaly detection algorithm that isolates observations by randomly partitioning features. Anomalies require fewer splits to isolate (shorter path length) because they occupy sparse regions of feature space.

### Formula
```
Anomaly score:
s(x, n) = 2^(-E[h(x)] / c(n))

where:
  h(x) = path length to isolate observation x
  E[h(x)] = average path length across isolation trees
  c(n) = average path length for n samples (normalization)
  c(n) = 2H(n-1) - (2(n-1)/n)  [H = harmonic number]

Score > 0.6 → likely anomaly
Score > 0.7 → strong anomaly signal
```

### Outputs
- Anomaly score per observation ∈ [0, 1]
- Binary label (anomaly vs. normal)
- Feature importance for isolation (approximate)

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | n × p numeric matrix | Entity feature vectors |
| n_estimators | Integer | Number of trees (100–300 typical) |
| contamination | Float | Expected anomaly fraction (0.05–0.15) |
| Output | Float ∈ [0,1] | Anomaly score per record |

### Assumptions
- Anomalies are few and different from normal
- Features are numeric
- Anomalies occupy lower-density regions of feature space
- No distributional assumption

### Limitations
- Does not explain why an entity is anomalous
- Contamination parameter requires domain knowledge
- Can miss anomalies that form tight clusters
- Feature selection significantly impacts performance

### Cybersecurity Use Case
**Multi-Feature Host Anomaly Detection**

With features [dns_query_count, unique_domains, entropy_of_domains, bytes_out, unique_ports], Isolation Forest identifies hosts that are simultaneously unusual across multiple dimensions. Unlike Z-score (which checks each metric independently), Isolation Forest catches entities that are moderately anomalous across all features simultaneously — a pattern typical of low-and-slow exfiltration.

Also used for:
- User behavioral anomaly scoring (UEBA)
- Network flow anomaly detection
- Log-based insider threat detection
- Cloud API abuse detection

### Splunk SPL Example (MLTK)
```spl
index=network
| bucket _time span=1h
| stats
    dc(query) as unique_domains,
    count as dns_count,
    avg(query_length) as avg_query_len,
    dc(record_type) as unique_rtypes
  by _time, src_ip
| fit IsolationForest unique_domains dns_count avg_query_len unique_rtypes
    n_estimators=100 contamination=0.05 into dns_isoforest_model
| where predicted_anomaly=-1
| sort - anomaly_score
| table _time, src_ip, unique_domains, dns_count, avg_query_len, anomaly_score
```

---

## 5. Local Outlier Factor (LOF)

### What It Analyzes
Measures the local density of an observation relative to its k nearest neighbors. Points in lower-density regions than their neighbors receive high LOF scores — meaning they're locally anomalous even if not globally extreme.

### Formula
```
Reachability distance:
reach-dist_k(p,o) = max(k-dist(o), d(p,o))

Local reachability density:
lrd_k(p) = 1 / (Σ_o∈Nk(p) reach-dist_k(p,o) / |Nk(p)|)

LOF score:
LOF_k(p) = (Σ_o∈Nk(p) lrd_k(o) / lrd_k(p)) / |Nk(p)|

LOF > 1 → denser than neighbors (normal)
LOF >> 1 → sparser than neighbors (anomalous)
```

### Outputs
- LOF score per observation (unbounded ≥ 1)
- k-nearest neighbor set per observation
- Reachability distances

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | n × p numeric matrix | Feature vectors |
| k | Integer | Number of neighbors (10–50 typical) |
| Output | Float ≥ 1 | LOF score |
| Flag | Boolean | True if LOF > threshold (e.g., 2.0) |

### Assumptions
- Anomalies are locally sparse (low density relative to neighbors)
- Features are numeric and meaningful distance metric exists
- k selection impacts sensitivity/specificity trade-off

### Limitations
- Sensitive to k selection
- Computationally expensive O(n²) for large datasets
- High LOF may result from genuine cluster boundaries, not anomalies
- Requires standardized features for meaningful distances

### Cybersecurity Use Case
**Detecting Stealthy Lateral Movement Within Peer Groups**

An attacker compromising a service account and accessing a small number of novel systems may not stand out in global Z-score analysis. LOF catches this by comparing the account's behavior against its local peer group (similar accounts in the same department) — revealing that within its neighborhood, the behavior is anomalously sparse.

### Splunk SPL Example (MLTK)
```spl
index=auth
| bucket _time span=1d
| stats
    dc(dest_host) as unique_targets,
    dc(src_ip) as unique_sources,
    count as auth_count
  by _time, user
| fit LocalOutlierFactor k=10 unique_targets unique_sources auth_count
    into user_lof_model
| where lof_score > 2.0
| sort - lof_score
| table _time, user, unique_targets, unique_sources, auth_count, lof_score
```

---

## 6. DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

### What It Analyzes
Clusters points based on density, identifying core points (surrounded by ≥ minPts within ε distance), border points, and noise points. Noise points are anomalies. Does not require pre-specifying k; discovers arbitrary cluster shapes.

### Formula
```
Core point: |Nε(p)| ≥ minPts
  where Nε(p) = {q : dist(p,q) ≤ ε}

Border point: |Nε(p)| < minPts but p ∈ Nε(core point)

Noise point: neither core nor border → ANOMALY

Distance metric: Euclidean (default), cosine, Manhattan
```

### Outputs
- Cluster label per observation (-1 = noise/anomaly)
- Core, border, noise classification
- Number of clusters discovered
- Cluster density statistics

### Input/Output Specification
| Parameter | Type | Description |
|-----------|------|-------------|
| Input | n × p feature matrix | Standardized security metrics |
| ε (epsilon) | Float | Neighborhood radius |
| minPts | Integer | Minimum points for core classification |
| Output | Integer per record | Cluster label (-1 = anomaly) |

### Assumptions
- Anomalies are in low-density regions
- ε and minPts must be tuned for the dataset
- Works well with arbitrary cluster shapes
- Robust to outliers — noise points are explicitly handled

### Limitations
- ε and minPts are sensitive hyperparameters (use k-distance plot to choose ε)
- Struggles with varying density clusters
- High-dimensional data requires dimensionality reduction first
- Not suitable for online/streaming use cases

### Cybersecurity Use Case
**C2 Beaconing Cluster Detection**

Beaconing hosts form tight clusters in [connection_interval, jitter, bytes_per_connection] space. DBSCAN naturally finds these clusters regardless of shape. Noise points are either highly anomalous individual hosts or genuine outliers. Unlike K-Means, DBSCAN can identify multiple distinct C2 families operating simultaneously with different profiles.

Also used for:
- Grouping similar phishing domains (typosquatting clusters)
- Identifying distinct attack waves in network traffic
- Finding clusters of related malware samples

### Splunk SPL Example (MLTK)
```spl
index=network
| bucket _time span=1h
| stats
    avg(conn_interval) as avg_interval,
    stdev(conn_interval) as jitter,
    avg(bytes_per_conn) as avg_bytes,
    count as conn_count
  by _time, src_ip, dest_ip
| fit DBSCAN eps=0.5 min_samples=5 avg_interval jitter avg_bytes conn_count
    into beacon_dbscan_model
| where cluster=-1
| sort - jitter
| table _time, src_ip, dest_ip, avg_interval, jitter, avg_bytes, cluster
```

---

## Summary: Multivariate Method Selection Guide

| Scenario | Method | Key Advantage |
|----------|--------|--------------|
| High-dimensional feature reduction | PCA | Reduces noise, enables visualization |
| Peer group segmentation | K-Means | Fast, scalable grouping |
| Malware family taxonomy | Hierarchical | No k required, reveals relationships |
| Multi-feature host anomaly scoring | Isolation Forest | Fast, no distributional assumptions |
| Local peer comparison for stealthy threats | LOF | Catches low-and-slow in peer context |
| Beaconing cluster discovery | DBSCAN | Arbitrary shapes, noise = anomaly |
| Combined pipeline | PCA → Isolation Forest | Reduce dimension, then score anomalies |
