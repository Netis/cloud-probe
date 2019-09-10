# 摘要
&emsp;&emsp;随着应用开发和部署流程进一步跟上需求迭代速度，调度资源更灵活、方便集群化部署的容器架构逐渐推广开来。相比虚拟机为单位的云架构，封闭程度更高的容器化应用更难以实现流量采集。本文介绍了Kubernetes环境流量采集的三种方案。<br/>

# 需要解决的问题
&emsp;&emsp;Kubernetes架构中，应用连同其依赖组件被打包为高度独立的单元，称为「容器」。容器化的业务应用尽可能降低了对外部环境的依赖程度，因此可以由控制器快速创建、配置和调整，灵活性非常高。但容器是一个相对完整而封闭的结构单元，无法直接在其镜像内部署流量采集组件。<br/>

# 技术背景
&emsp;&emsp;应用虽然被打包为一个个容器，但系统对其管理是通过名为Pod的结构实现的：一个Pod中可以放置单个或多个应用容器，这些同Pod的容器共享Pod内的网络、存储等资源，彼此之间可见。<br/>
&emsp;&emsp;通过补丁，可以避免定义整个对象，只需要定义希望更改的部分。只需要定义新增的元素就可以更新一个列表。列表中已有的元素仍然保留，新增的元素和已有的元素会被合并。<br/>
&emsp;&emsp;准入控制器是一段代码，会拦截 Kubernetes API Server 收到的请求，拦截发生在认证和鉴权完成之后，对象进行持久化之前。可以定义两种类型的 Admission webhook：Validating 和 Mutating。Validating 类型的 Webhook 可以根据自定义的准入策略决定是否拒绝请求；Mutating 类型的 Webhook 可以根据自定义配置来对请求进行编辑。<br/>

# 方案一：修改 yaml 配置文件
* 直接修改YAML文件，直接将流量采集的镜像部署到被监控应用的同一个POD中去：
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
 name: nginx-deployment
spec:
 selector:
   matchLabels:
     app: nginx
 replicas: 2
 template:
   metadata:
     labels:
       app: nginx
   spec:
     containers:
     - name: nginx
       image: nginx:1.7.9
       ports:
       - containerPort: 80
     - name: monitor
       image: docker.io/s1240zsw/centos-packet-agent:v1
       stdin: true
       tty: true
```

# 方案二：补丁命令
* Patch deployment，应用部署后通过修改补丁将流量采集的镜像部署到被监控应用的同一个POD中去
```console
kubectl patch deployment nginx-deployment -p '{"spec":{"template":{"spec":{"containers":[{"name":"monitor","image":"docker.io/s1240zsw/centos-packet-agent:v1","stdin":true,"tty":true}]}}}}'
```

# 方案三：WebHook
* WebHook，通过监控pod的启动停止行为，在需要监控的pod启动的时候自动将将流量采集的镜像部署到被监控应用的同一个POD中去
    1. 生成密钥
	```console
	./webhook-create-signed-cert.sh \
	--service sidecar-injector-webhook-svc \
	--secret sidecar-injector-webhook-certs \
	--namespace default
	```

		* webhook-create-signed-cert.sh
		```bash
		#!/bin/bash
		set -e
		usage() {
		    cat <<EOF
		Generate certificate suitable for use with an sidecar-injector webhook service.
		This script uses k8s CertificateSigningRequest API to a generate a
		certificate signed by k8s CA suitable for use with sidecar-injector webhook
		services. This requires permissions to create and approve CSR. See
		https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster for
		detailed explantion and additional instructions.
		The server key/cert k8s CA cert are stored in a k8s secret.
		usage: ${0} [OPTIONS]
		The following flags are required.
		       --service          Service name of webhook.
		       --namespace        Namespace where webhook service and secret reside.
		       --secret           Secret name for CA certificate and server certificate/key pair.
		EOF
		    exit 1
		}
		
		while [[ $# -gt 0 ]]; do
		    case ${1} in
		        --service)
		            service="$2"
		            shift
		            ;;
		        --secret)
		            secret="$2"
		            shift
		            ;;
		        --namespace)
		            namespace="$2"
		            shift
		            ;;
		        *)
		            usage
		            ;;
		    esac
		    shift
		done
		
		[ -z ${service} ] && service=sidecar-injector-webhook-svc
		[ -z ${secret} ] && secret=sidecar-injector-webhook-certs
		[ -z ${namespace} ] && namespace=default
		
		if [ ! -x "$(command -v openssl)" ]; then
		    echo "openssl not found"
		    exit 1
		fi
		
		csrName=${service}.${namespace}
		tmpdir=$(mktemp -d)
		echo "creating certs in tmpdir ${tmpdir} "
		
		cat <<EOF >> ${tmpdir}/csr.conf
		[req]
		req_extensions = v3_req
		distinguished_name = req_distinguished_name
		[req_distinguished_name]
		[ v3_req ]
		basicConstraints = CA:FALSE
		keyUsage = nonRepudiation, digitalSignature, keyEncipherment
		extendedKeyUsage = serverAuth
		subjectAltName = @alt_names
		[alt_names]
		DNS.1 = ${service}
		DNS.2 = ${service}.${namespace}
		DNS.3 = ${service}.${namespace}.svc
		EOF
		
		openssl genrsa -out ${tmpdir}/server-key.pem 2048
		openssl req -new -key ${tmpdir}/server-key.pem -subj "/CN=${service}.${namespace}.svc" -out ${tmpdir}/server.csr -config ${tmpdir}/csr.conf
		
		# clean-up any previously created CSR for our service. Ignore errors if not present.
		kubectl delete csr ${csrName} 2>/dev/null || true
		
		# create  server cert/key CSR and  send to k8s API
		cat <<EOF | kubectl create -f -
		apiVersion: certificates.k8s.io/v1beta1
		kind: CertificateSigningRequest
		metadata:
		  name: ${csrName}
		spec:
		  groups:
		  - system:authenticated
		  request: $(cat ${tmpdir}/server.csr | base64 | tr -d '\n')
		  usages:
		  - digital signature
		  - key encipherment
		  - server auth
		EOF
		
		# verify CSR has been created
		while true; do
		    kubectl get csr ${csrName}
		    if [ "$?" -eq 0 ]; then
		        break
		    fi
		done
		
		# approve and fetch the signed certificate
		kubectl certificate approve ${csrName}
		# verify certificate has been signed
		for x in $(seq 10); do
		    serverCert=$(kubectl get csr ${csrName} -o jsonpath='{.status.certificate}')
		    if [[ ${serverCert} != '' ]]; then
		        break
		    fi
		    sleep 1
		done
		
		if [[ ${serverCert} == '' ]]; then
		    echo "ERROR: After approving csr ${csrName}, the signed certificate did not appear on the resource. Giving up after 10 attempts." >&2
		    exit 1
		fi
		
		echo ${serverCert} | openssl base64 -d -A -out ${tmpdir}/server-cert.pem
		# create the secret with CA cert and server cert/key
		kubectl create secret generic ${secret} \
		        --from-file=key.pem=${tmpdir}/server-key.pem \
		        --from-file=cert.pem=${tmpdir}/server-cert.pem \
		        --dry-run -o yaml |
		    kubectl -n ${namespace} apply -f -
	```

	2. 部署密钥
	```console
cat mutatingwebhook.yaml | \
    webhook-patch-ca-bundle.sh > \
    mutatingwebhook-ca-bundle.yaml
	```

		* webhook-patch-ca-bundle.sh
		```bash
#!/bin/bash
		ROOT=$(cd $(dirname $0)/../../; pwd)
		set -o errexit
		set -o nounset
		set -o pipefail
		export CA_BUNDLE=$(kubectl config view --raw --minify --flatten -o 		jsonpath='{.clusters[].cluster.certificate-authority-data}')
		
		if command -v envsubst >/dev/null 2>&1; then
		    envsubst
		else
		    sed -e "s|\${CA_BUNDLE}|${CA_BUNDLE}|g"
		fi
	```

		* mutatingwebhook.yaml
		```yaml
		apiVersion: admissionregistration.k8s.io/v1beta1
		kind: MutatingWebhookConfiguration
		metadata:
		  name: sidecar-injector-webhook-cfg
		  labels:
		    app: sidecar-injector
		webhooks:
		  - name: sidecar-injector.morven.me
		    clientConfig:
		      service:
		        name: sidecar-injector-webhook-svc
		        namespace: default
		        path: "/mutate"
		      caBundle: ${CA_BUNDLE}
		    rules:
		      - operations: [ "CREATE" ]
		        apiGroups: [""]
		        apiVersions: ["v1"]
		        resources: ["pods"]
		    namespaceSelector:
		      matchLabels:
		        sidecar-injector: enabled
	```

	3. 部署流量监控镜像
	```bash
kubectl create -f configmap.yaml
kubectl create -f deployment.yaml
kubectl create -f service.yaml
kubectl create -f mutatingwebhook-ca-bundle.yaml
	```

		* configmap.yaml
		```yaml
		apiVersion: v1
		kind: ConfigMap
		metadata:
		  name: sidecar-injector-webhook-configmap
		data:
		  sidecarconfig.yaml: |
		    containers:
		      - name: sidecar-monitor
		        image: docker.io/s1240zsw/centos-packet-agent:v1
		        stdin: true
		        tty: true
		```

		* deployment.yaml
		```yaml
		apiVersion: extensions/v1beta1
		kind: Deployment
		metadata:
		  name: sidecar-injector-webhook-deployment
		  labels:
		    app: sidecar-injector
		spec:
		  replicas: 1
		  template:
		    metadata:
		      labels:
		        app: sidecar-injector
		    spec:
		      containers:
		        - name: sidecar-injector
		          image: morvencao/sidecar-injector:v1
		          imagePullPolicy: IfNotPresent
		          args:
		            - -sidecarCfgFile=/etc/webhook/config/sidecarconfig.yaml
		            - -tlsCertFile=/etc/webhook/certs/cert.pem
		            - -tlsKeyFile=/etc/webhook/certs/key.pem
		            - -alsologtostderr
		            - -v=4
		            - 2>&1
		          volumeMounts:
		            - name: webhook-certs
		              mountPath: /etc/webhook/certs
		              readOnly: true
		            - name: webhook-config
		              mountPath: /etc/webhook/config
		      volumes:
		        - name: webhook-certs
		          secret:
		            secretName: sidecar-injector-webhook-certs
		        - name: webhook-config
		          configMap:
		            name: sidecar-injector-webhook-configmap
```

		* service.yaml
		```yaml
		apiVersion: v1
		kind: Service
		metadata:
		  name: sidecar-injector-webhook-svc
		  labels:
		    app: sidecar-injector
		spec:
		  ports:
		  - port: 443
		    targetPort: 443
		  selector:
		    app: sidecar-injector
		```

	4. 给需要监控的应用打上标签
	```console
	kubectl patch deployment nginx-deployment -p '{"spec":{"template":{"metadata":{"annotations":{"sidecar-injector-webhook.morven.me/inject": "true"}}}}}'
	```

# 结论
&emsp;&emsp;优先采用修改yaml文件的方法，如果没有修改yaml文件的权限，那么可以采用Patch deployment方法。如果以上方法都不能用最后再采用WebHook方法。<br/>

# 参考
1. [Istio Sidecar 注入过程解密](https://istio.io/zh/blog/2019/data-plane-setup/)
2. [Diving into Kubernetes MutatingAdmissionWebhook](https://github.com/morvencao/kube-mutating-webhook-tutorial/blob/master/medium-article.md)
