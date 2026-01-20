# Cartesi Node Dockerfile for EigenCloud deployment
# This packages the RISC-V machine snapshot into a Cartesi rollups node

FROM cartesi/rollups-node:1.5.1

# Set snapshot directory
ENV CARTESI_SNAPSHOT_DIR=/usr/share/rollups-node/snapshot
ENV CARTESI_HTTP_ADDRESS=0.0.0.0

# Copy the machine snapshot from cartesi build output
COPY --chown=cartesi:cartesi .cartesi/image /usr/share/rollups-node/snapshot

# Labels for EigenCloud
LABEL tee.launch_policy.log_redirect="always"
LABEL tee.launch_policy.monitoring_memory_allow="always"

EXPOSE 10000

CMD ["cartesi-rollups-node"]
