# Introduction

ITU-MiniTwit is a Twitter-like microblogging service from the original Flask codebase that this course provides. Over the semester, we refactored it into a Go application backed by PostgreSQL, deployed in containers on a single-node Docker Swarm hosted at Hetzner. We had three main motivations for picking go: We wanted to challenge ourselves by doing something new, prioritized the performance of a pre-compiled language, and the static typing of go seemed accesible. The rest of this report describes how we provisioned, built, deployed, observed, and secured the system.
