Hackathon access bundle
=======================

Hi ICHALLALEN Maksen (group: equipe-14),

This bundle contains:

  * kubeconfig-equipe-14.yaml
      Save this file somewhere safe, then use it with kubectl:
          export KUBECONFIG=/path/to/kubeconfig-equipe-14.yaml
          kubectl get nodes

  * ai-endpoints-key.txt
      The single line inside this file is an AI Endpoints access key for
      the OVHcloud AI Endpoints API (https://endpoints.ai.cloud.ovh.net).
      Use it as a Bearer token:
          export OVH_AI_ENDPOINTS_ACCESS_TOKEN=$(cat ai-endpoints-key.txt)
      The key is shared with your group — keep it secret.

Have fun!
