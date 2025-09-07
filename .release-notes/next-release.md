## Workflow Updates for Releases

Many many release iterations to get the changelog-bot rotating appropriately.

## Added Static Builds by Github Workflows

Github workflows now generate a static binary which should be usable on any Linux distribution.

## Full runthrough of build process

This is another attempt to get the full runthough of the build process from start to finish.

## Fix concurrency error in release.yml file

It appears I created a concurrency error by missing a "needs:" in the yaml file resulting in multiple executions of things that shouldn't.  This should fix this.

## Updated release-bot version

As we are generating our own packages as opposed to having release-bot-action do it as a part of "publish-release-notes", we need the latest version.  The latest version checks for an existing package (which we have), and modifies our package as opposed to attempting to generate a new one and fail.

