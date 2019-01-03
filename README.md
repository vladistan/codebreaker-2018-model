# CodeBreaker Challenge 2018 -- Model

This is a model of Ransomware.  We only have two shared library files, so we
need to stub / mock the rest of the system.  This way we can observe the way
our Ransomware is supposed to work and find it's weak points.


The model is CMake + CppUTest project.  The easiest setup is on Mac + HomeBrew.
Just run commands below

```
brew install cmake
brew install cpputest
brew install openssl
```

Then we need to generate system specific Makefile for our project

```
cmake .
```

And now we can build

```
make
```

Once we built we can run the RunAllTests

```
./RunAllTests
```

if everything is working you should see output like this:

```
.......
OK (7 tests, 7 ran, 7 checks, 0 ignored, 0 filtered out, 1 ms)

```
