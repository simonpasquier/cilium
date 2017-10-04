apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: cilium
  namespace: kube-system
spec:
  template:
    metadata:
      labels:
        k8s-app: cilium
        kubernetes.io/cluster-service: "true"
      annotations:
        scheduler.alpha.kubernetes.io/tolerations: >-
          [{"key":"dedicated","operator":"Equal","value":"master","effect":"NoSchedule"}]
    spec:
      serviceAccountName: cilium
      containers:
      - image: cilium:local_build
        imagePullPolicy: Never
        name: cilium-agent
        command: [ "cilium-agent" ]
        args:
          - "--debug=$(CILIUM_DEBUG)"
          - "-t"
          - "vxlan"
          - "--kvstore"
          - "etcd"
          - "--kvstore-opt"
          - "etcd.config=/var/lib/etcd-config/etcd.config"
          - "--disable-ipv4=$(DISABLE_IPV4)"
        lifecycle:
          postStart:
            exec:
              command:
                - "/cni-install.sh"
          preStop:
            exec:
              command:
                - "/cni-uninstall.sh"
        env:
          - name: "K8S_NODE_NAME"
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: "CILIUM_DEBUG"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                key: debug
          - name: "DISABLE_IPV4"
            valueFrom:
              configMapKeyRef:
                name: cilium-config
                key: disable-ipv4
        livenessProbe:
          exec:
            command:
            - cilium
            - status
          initialDelaySeconds: 180
          failureThreshold: 10
          periodSeconds: 10
        readinessProbe:
          exec:
            command:
            - cilium
            - status
          initialDelaySeconds: 180
          periodSeconds: 15
        volumeMounts:
          - name: bpf-maps
            mountPath: /sys/fs/bpf
          - name: cilium-run
            mountPath: /var/run/cilium
          - name: cni-path
            mountPath: /host/opt/cni/bin
          - name: etc-cni-netd
            mountPath: /host/etc/cni/net.d
          - name: docker-socket
            mountPath: /var/run/docker.sock
            readOnly: true
          - name: etcd-config-path
            mountPath: /var/lib/etcd-config
            readOnly: true
          - name: etcd-secrets
            mountPath: /var/lib/etcd-secrets
            readOnly: true
        securityContext:
          capabilities:
            add:
              - "NET_ADMIN"
          privileged: true
      hostNetwork: true
      volumes:
        - name: cilium-run
          hostPath:
            path: /var/run/cilium
        - name: cni-path
          hostPath:
            path: /opt/cni/bin
        - name: bpf-maps
          hostPath:
            path: /sys/fs/bpf
        - name: docker-socket
          hostPath:
            path: /var/run/docker.sock
        - name: etc-cni-netd
          hostPath:
              path: /etc/cni/net.d
        - name: etcd-config-path
          configMap:
            name: cilium-config
            items:
            - key: etcd-config
              path: etcd.config
        - name: etcd-secrets
          secret:
            secretName: cilium-etcd-secrets
      tolerations:
      - effect: NoSchedule
        key: node-role.kubernetes.io/master
      - effect: NoSchedule
        key: node.cloudprovider.kubernetes.io/uninitialized
        value: "true"

