
var compileButton = document.getElementById('compile');

// 为按钮添加点击事件处理函数
compileButton.addEventListener('click', function() {
    const exec = require('child_process').exec;
    // 要执行的命令
    const command = 'make build';
    // 执行命令
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`执行命令出错: ${error}`);
            return;
        }
        console.log(`命令输出: ${stdout}`);
    });
});
