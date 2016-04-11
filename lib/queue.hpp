#ifndef QUEUE_LIB
#define QUEUE_LIB

#include <memory>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>

/*
 Класс потокобезопасной очереди. При добавлении элемента оповещает один
 "ожидающий" поток о том, что поступили данные. Либо ожидание элемента в
 очереди длится timeout миллисекунд (чтобы была возможность прервать операцию).
*/
template<typename T>
class ts_queue
{
private:
	mutable std::mutex mut;
	std::queue<std::shared_ptr<T> > data_queue;
	std::condition_variable data_cond;
public:
	ts_queue()
	{}
	bool wait_and_pop(T& value, int timeout)
	{
		std::unique_lock<std::mutex> lk(mut);
		data_cond.wait_for(lk, std::chrono::milliseconds(timeout));
		if(data_queue.empty())
			return false;
		value=std::move(*data_queue.front());
		data_queue.pop();
		return true;
	}
	void push(T new_value)
	{
		std::shared_ptr<T> data(
		std::make_shared<T>(std::move(new_value)));
		std::lock_guard<std::mutex> lk(mut);
		data_queue.push(data);
		data_cond.notify_one();
	}
};

#endif // end QUEUE_LIB