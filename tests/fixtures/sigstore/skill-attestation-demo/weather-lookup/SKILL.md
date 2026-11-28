---
name: weather-lookup
description: Looks up the current weather for a city with the Open-Meteo API. A demo Skill for mago-ski published-by attestations.
permissions:
  network:
    allow: [api.open-meteo.com, geocoding-api.open-meteo.com]
    deny: "*"
  shell: true
requires:
  binaries: [curl, jq]
---
# Weather lookup

1. Find the city's coordinates:

   ```bash
   curl -s "https://geocoding-api.open-meteo.com/v1/search?name=Seoul&count=1" | jq '.results[0] | {latitude, longitude}'
   ```

2. Ask for the current weather at those coordinates:

   ```bash
   curl -s "https://api.open-meteo.com/v1/forecast?latitude=37.57&longitude=126.98&current=temperature_2m" | jq .current
   ```
