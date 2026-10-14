# vLLM 0.11 is built on CUDA 12.8, which a 570-series driver supports.
FROM vllm/vllm-openai:v0.11.0
# GeForce GPUs cannot use CUDA forward compatibility. Drop the bundled cuda-compat driver, otherwise
# nvidia-container-toolkit injects it at start-up and CUDA fails with "Error 804".
RUN rm -rf /usr/local/cuda-12.8/compat && \
    grep -rl "cuda-12.8/compat" /etc/ld.so.conf.d/ | xargs -r rm -f && ldconfig
ENTRYPOINT []
