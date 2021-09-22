# rwrt

A companion tool for Frida used to gather information on Android applications. 
The resulting output file is JSON which can be easily parsed by other applications.


For a quick overview of the project, see the blog post on [vvect.xyz](https://vvect.xyz/posts/rwrt/)

## Getting started

```sh
# Clone the repository
git clone https://github.com/vvect/rwrt $HOME/rwrt
# Setup an alias in your rc file
echo 'alias rwrt="python3 $HOME/rwrt/main.py"' >> $HOME/.zshrc
# Install the dependencies
cd $HOME/rwrt
pip install -r requirements.txt
```

## rwrtg

`rwrtg` uses the output created by `rwrt` to generate frida scripts that are easy to modify. 
