# xiaoya_emd_go

小雅元数据爬虫Golang版

# Docker Run

```shell
docker run -d \
    --name=xiaoya-emd-go \
    --restart=always \
    -p 8080:8080 \
    -v 媒体库目录:/media \
    ddsderek/xiaoya-emd-go:latest
```
